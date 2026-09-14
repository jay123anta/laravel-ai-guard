<?php

namespace JayAnta\AiGuard\Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JayAnta\AiGuard\Exceptions\UnsafeSqlException;
use JayAnta\AiGuard\Facades\AiGuard;
use JayAnta\AiGuard\Models\AiThreatLog;
use JayAnta\AiGuard\Tests\TestCase;

class SqlGuardTest extends TestCase
{
    public function test_read_only_queries_pass(): void
    {
        $result = AiGuard::checkSql("SELECT id, name FROM users WHERE name = 'x; DROP TABLE users' AND note = 'it''s' LIMIT 5;");

        $this->assertFalse($result['detected']);
        $this->assertSame(['users'], $result['tables']);

        $cte = AiGuard::checkSql(
            'WITH recent AS (SELECT * FROM orders WHERE created_at > ?) SELECT u.name, COUNT(*) FROM recent JOIN "users" u ON u.id = recent.user_id -- per user'."\n".'GROUP BY u.name',
            ['allowed_tables' => ['orders', 'users']]
        );
        $this->assertFalse($cte['detected'], (string) $cte['matched_pattern']);
        $this->assertSame(['orders', 'users'], $cte['tables']);

        $this->assertFalse(AiGuard::checkSql('SELECT EXTRACT(YEAR FROM created_at) AS y FROM users', ['allowed_tables' => ['users']])['detected']);
        $this->assertFalse(AiGuard::checkSql('select updated_at, deleted_at, created_by from users')['detected'], 'Column names are not keywords');
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function unsafeQueries(): array
    {
        return [
            'write statement' => ['DELETE FROM users', 'only SELECT queries are allowed'],
            'stacked statement' => ['SELECT 1; DROP TABLE users', 'more than one statement'],
            'mysql -- without space' => ['SELECT 1--1; DROP TABLE users', 'more than one statement'],
            'string hides nothing' => ["SELECT '--' AS a; DROP TABLE users", 'more than one statement'],
            'data-modifying cte' => ['WITH x AS (DELETE FROM users RETURNING *) SELECT * FROM x', 'write or admin keyword: delete'],
            'into outfile' => ["SELECT * INTO OUTFILE '/tmp/x' FROM users", 'write or admin keyword: into'],
            'row lock' => ['SELECT * FROM users FOR UPDATE', 'write or admin keyword: update'],
            'share lock' => ['SELECT * FROM users FOR SHARE', 'row locking'],
            'sleep' => ['SELECT pg_sleep(10)', 'dangerous function: pg_sleep'],
            'file read' => ["SELECT LOAD_FILE('/etc/passwd')", 'dangerous function: load_file'],
            'catalog' => ['SELECT * FROM information_schema.tables', 'system table: information_schema'],
            'sqlite catalog' => ['SELECT sql FROM sqlite_master', 'system table: sqlite_master'],
            'mysql schema' => ['SELECT * FROM mysql.user', 'system table: mysql'],
            'backslash ambiguity' => ["SELECT * FROM users WHERE name = 'it\\'s' ; DROP TABLE users; SELECT '", 'backslash escape in a string literal'],
            'executable comment' => ['SELECT 1 /*!50000 , (SELECT 1) */', 'executable comment'],
            'unterminated' => ["SELECT 'abc", 'unterminated string literal'],
            'unterminated identifier' => ['SELECT * FROM "users; DROP TABLE users', 'unterminated quoted identifier'],
            'unterminated backtick' => ['SELECT * FROM `users; DROP TABLE users', 'unterminated quoted identifier'],
            'mysql hash comment' => ["SELECT 1 #\n; DROP TABLE users", 'ambiguous "#" (a comment in MySQL, an operator in PostgreSQL)'],
            'empty' => [' ; ', 'empty query'],
            'pg xml dump' => ["SELECT query_to_xml('SELECT * FROM users', true, true, '')", 'dangerous function: query_to_xml'],
            'pg table dump' => ["SELECT database_to_xml(true, false, '')", 'dangerous function: database_to_xml'],
            'pg catalog' => ['SELECT * FROM pg_shadow', 'system table: pg_shadow'],
            'sqlite pragma function' => ["SELECT * FROM pragma_table_info('users')", 'system table: pragma_table_info'],
        ];
    }

    /**
     * @dataProvider unsafeQueries
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('unsafeQueries')]
    public function test_unsafe_queries_are_refused(string $sql, string $reason): void
    {
        $result = AiGuard::checkSql($sql);

        $this->assertTrue($result['detected']);
        $this->assertSame('unsafe_sql', $result['threat_type']);
        $this->assertSame($reason, $result['matched_pattern']);
    }

    public function test_table_allow_list(): void
    {
        $options = ['allowed_tables' => ['users']];

        $this->assertSame('table not allowed: secrets', AiGuard::checkSql('SELECT * FROM secrets', $options)['matched_pattern']);
        $this->assertSame('table not allowed: secrets', AiGuard::checkSql('SELECT * FROM users u, secrets s', $options)['matched_pattern']);
        $this->assertSame('table not allowed: other.users', AiGuard::checkSql('SELECT * FROM other.users', $options)['matched_pattern']);
        $this->assertSame('table not allowed: secrets', AiGuard::checkSql('SELECT * FROM users LEFT JOIN secrets ON 1 = 1', $options)['matched_pattern']);
        $this->assertSame('table not allowed: secrets', AiGuard::checkSql('SELECT * FROM users JOIN secrets ON 1 = 1', $options)['matched_pattern']);
        $this->assertSame('table not allowed: secrets', AiGuard::checkSql('SELECT * FROM users WHERE id IN (SELECT user_id FROM secrets)', $options)['matched_pattern']);
        $this->assertSame(['users', 'secrets'], AiGuard::checkSql('SELECT * FROM users CROSS JOIN secrets')['tables']);
        $this->assertSame('dangerous function: pg_stat_activity', AiGuard::checkSql('SELECT pg_stat_activity()', ['deny_functions' => ['pg_stat_activity']])['matched_pattern']);
    }

    public function test_every_spelling_of_a_table_reference_is_seen(): void
    {
        $options = ['allowed_tables' => ['orders']];

        // Each of these hid the table from the allow-list entirely
        foreach ([
            'SELECT * FROM`secrets`',
            'SELECT * FROM"secrets"',
            'SELECT * FROM (secrets)',
            'SELECT * FROM ((secrets))',
            'SELECT * FROM orders, (secrets)',
            'SELECT * FROM orders JOIN (secrets) s ON 1 = 1',
            'SELECT * FROM orders STRAIGHT_JOIN secrets ON 1 = 1',
        ] as $sql) {
            $this->assertSame('table not allowed: secrets', AiGuard::checkSql($sql, $options)['matched_pattern'], $sql);
        }

        // An unterminated dollar-quote hides everything after it, including a second statement
        $this->assertSame(
            'unterminated dollar-quoted string',
            AiGuard::checkSql('SELECT 1 FROM orders WHERE a = $$ ; DROP TABLE orders', $options)['matched_pattern']
        );

        // Quoted names that are allowed still pass, schema qualifier and all
        $allowed = AiGuard::checkSql('SELECT * FROM "orders" o JOIN shop."products" p ON p.id = o.product_id', ['allowed_tables' => ['orders', 'shop.products']]);
        $this->assertFalse($allowed['detected'], (string) $allowed['matched_pattern']);
        $this->assertSame(['orders', 'shop.products'], $allowed['tables']);
    }

    public function test_a_common_table_expression_only_stands_for_itself_after_its_own_body(): void
    {
        $options = ['allowed_tables' => ['orders']];

        // A CTE named after a real table: the reference inside its body is still the table
        $this->assertSame('table not allowed: users', AiGuard::checkSql('WITH users AS (SELECT id FROM users) SELECT * FROM users', $options)['matched_pattern']);
        $this->assertSame(['users'], AiGuard::checkSql('WITH users AS (SELECT id FROM users) SELECT * FROM users')['tables']);

        // "x AS (...)" outside the WITH list declares nothing
        $this->assertSame(
            'table not allowed: users',
            AiGuard::checkSql('SELECT rank() OVER users FROM orders WINDOW users AS (PARTITION BY id) UNION SELECT id FROM users', $options)['matched_pattern']
        );
        $this->assertSame('table not allowed: users', AiGuard::checkSql('SELECT (SELECT 1) AS users FROM users', $options)['matched_pattern']);

        // Several CTEs, one of them recursive and one with a column list, still resolve to themselves
        $chained = AiGuard::checkSql(
            'WITH RECURSIVE tree (id) AS (SELECT id FROM orders), totals AS (SELECT sum(x) FROM tree) SELECT * FROM tree JOIN totals ON 1 = 1',
            $options
        );
        $this->assertFalse($chained['detected'], (string) $chained['matched_pattern']);
        $this->assertSame(['orders'], $chained['tables']);
    }

    public function test_run_read_only_caps_rows_and_refuses_unsafe_sql(): void
    {
        Schema::create('products', function (Blueprint $table) {
            $table->id();
            $table->string('name');
        });
        DB::table('products')->insert([['name' => 'a'], ['name' => 'b'], ['name' => 'c']]);

        $this->assertSame([['name' => 'a'], ['name' => 'b'], ['name' => 'c']], AiGuard::runReadOnlySql('SELECT name FROM products ORDER BY id'));
        $this->assertSame([['name' => 'b']], AiGuard::runReadOnlySql('SELECT name FROM products WHERE name = ?', ['b']));

        config()->set('ai-guard.llm_guard.sql.max_rows', 2);
        $this->refreshAiGuard();
        $this->assertCount(2, AiGuard::runReadOnlySql('SELECT name FROM products'));

        // Valid SQL is run as written — it used to be wrapped in a derived table, which a
        // trailing comment or two columns of the same name would break
        $this->assertSame([['name' => 'a'], ['name' => 'b']], AiGuard::runReadOnlySql("SELECT name FROM products ORDER BY id -- oldest first\n"));
        $this->assertCount(2, AiGuard::runReadOnlySql('SELECT p.id, q.id FROM products p JOIN products q ON 1 = 1'));

        try {
            AiGuard::runReadOnlySql('DELETE FROM products');
            $this->fail('Unsafe SQL ran');
        } catch (UnsafeSqlException $e) {
            $this->assertSame('Refused model-written SQL: only SELECT queries are allowed', $e->getMessage());
        }

        $this->assertSame(3, DB::table('products')->count());
        $log = AiThreatLog::sole();
        $this->assertSame('unsafe_sql', $log->threat_type);
        $this->assertSame('blocked', $log->action_taken);
        $this->assertFalse(DB::transactionLevel() > 0, 'The read-only transaction is closed');
    }

    public function test_run_read_only_checks_with_the_options_it_is_given(): void
    {
        Schema::create('products', function (Blueprint $table) {
            $table->id();
            $table->string('name');
        });

        // Checking with one set of options and running with another is the documented flow,
        // so the run has to apply the allow-list it was handed
        try {
            AiGuard::runReadOnlySql('SELECT name FROM products', [], null, ['allowed_tables' => ['orders']]);
            $this->fail('The allowed tables passed to runReadOnlySql were ignored');
        } catch (UnsafeSqlException $e) {
            $this->assertSame('Refused model-written SQL: table not allowed: products', $e->getMessage());
        }

        $this->assertSame([], AiGuard::runReadOnlySql('SELECT name FROM products', [], null, ['allowed_tables' => ['products']]));
    }
}
