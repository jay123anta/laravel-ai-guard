<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Support\Facades\DB;
use JayAnta\AiGuard\Exceptions\UnsafeSqlException;
use JayAnta\AiGuard\Support\ReportsThreats;

/**
 * Checks SQL written by a model (text-to-SQL, "ask your data" features) before it runs:
 * a single read-only statement, allowed tables only, no file, sleep, or admin functions.
 * Wherever the SQL could be read two ways, the check fails closed.
 *
 * runReadOnly() adds a row cap and a rolled-back (and, on MySQL/PostgreSQL, READ ONLY)
 * transaction. Still give the connection a database user with SELECT rights only: this is
 * a second line of defence, not a substitute for one.
 */
class SqlGuard
{
    use ReportsThreats;

    private const WRITE_KEYWORDS = [
        'insert', 'update', 'delete', 'merge', 'upsert', 'drop', 'alter', 'create', 'truncate', 'rename',
        'grant', 'revoke', 'call', 'exec', 'execute', 'copy', 'attach', 'detach', 'pragma', 'vacuum',
        'reindex', 'lock', 'unlock', 'handler', 'into', 'commit', 'rollback', 'savepoint', 'prepare', 'deallocate',
    ];

    private const FUNCTIONS = [
        'sleep', 'benchmark', 'pg_sleep', 'pg_sleep_for', 'pg_sleep_until', 'waitfor', 'load_file', 'pg_read_file',
        'pg_read_binary_file', 'pg_ls_dir', 'pg_stat_file', 'pg_read_server_files', 'lo_import', 'lo_export', 'lo_get',
        'dblink', 'dblink_exec', 'xp_cmdshell', 'sp_executesql', 'openrowset', 'opendatasource', 'utl_http', 'utl_file',
        'dbms_pipe', 'sys_eval', 'sys_exec', 'load_extension', 'readfile', 'writefile', 'randomblob', 'zeroblob',
        'pg_terminate_backend', 'pg_cancel_backend', 'set_config', 'current_setting', 'get_lock', 'release_lock',
        // These take SQL or a table name as a string literal, which the literal stripper blanks out
        'query_to_xml', 'query_to_xmlschema', 'query_to_xml_and_xmlschema', 'table_to_xml', 'table_to_xmlschema',
        'table_to_xml_and_xmlschema', 'schema_to_xml', 'schema_to_xmlschema', 'schema_to_xml_and_xmlschema',
        'database_to_xml', 'database_to_xmlschema', 'database_to_xml_and_xmlschema',
    ];

    private const SYSTEM_TABLES = [
        'information_schema', 'performance_schema',
    ];

    // Whole families of catalog objects, matched by prefix (pg_class, sqlite_master, pragma_table_info, …)
    private const SYSTEM_PREFIXES = '/\b(pg_[a-z_]+|sqlite_[a-z_]+|pragma_[a-z_]+)\b/';

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * @return array{detected: bool, threat_type: string|null, threat_source: string, confidence_score: int, matched_pattern: string|null, payload_snippet: string, tables: array<int, string>}
     */
    public function check(string $sql, array $options = []): array
    {
        $options = array_merge((array) ($this->config['llm_guard']['sql'] ?? []), $options);
        $tables = [];
        $reason = $this->violation($sql, $options, $tables);

        return [
            'detected' => $reason !== null,
            'threat_type' => $reason !== null ? 'unsafe_sql' : null,
            'threat_source' => 'llm_sql',
            'confidence_score' => $reason !== null ? 90 : 0,
            'matched_pattern' => $reason !== null ? mb_substr($reason, 0, 255) : null,
            'payload_snippet' => mb_substr($sql, 0, 500),
            'tables' => $tables,
        ];
    }

    /**
     * Check, then run the query with a row cap inside a transaction that is always rolled back.
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws UnsafeSqlException
     */
    public function runReadOnly(string $sql, array $bindings = [], ?string $connection = null, array $options = []): array
    {
        $options = array_merge((array) ($this->config['llm_guard']['sql'] ?? []), $options);
        $result = $this->check($sql, $options);

        if ($result['detected']) {
            $this->reportThreat($result, 'blocked');

            throw new UnsafeSqlException('Refused model-written SQL: '.$result['matched_pattern']);
        }

        $query = rtrim(trim($sql), "; \t\n\r");
        $maxRows = array_key_exists('max_rows', $options) ? $options['max_rows'] : 1000;
        $cap = is_numeric($maxRows) ? max(1, (int) $maxRows) : null;

        $db = DB::connection($connection ?? ($options['connection'] ?? null));
        $driver = $db->getDriverName();

        if (in_array($driver, ['mysql', 'mariadb'], true)) {
            $db->statement('SET TRANSACTION READ ONLY');
        }

        $db->beginTransaction();
        $rows = [];

        try {
            if ($driver === 'pgsql') {
                $db->statement('SET TRANSACTION READ ONLY');
            }

            // The cap is applied while reading rather than by wrapping the query in a derived
            // table: wrapping changes what valid SQL means (a trailing -- comment swallows the
            // closing parenthesis, and MySQL rejects duplicate column names in a subquery)
            $cursor = $db->cursor($query, $bindings);

            foreach ($cursor as $row) {
                $rows[] = (array) $row;

                if ($cap !== null && count($rows) >= $cap) {
                    break;
                }
            }

            // Finish with the statement before the transaction is rolled back
            unset($cursor);
        } finally {
            $db->rollBack();
        }

        return $rows;
    }

    /**
     * @param  array<int, string>  $tables
     */
    private function violation(string $sql, array $options, array &$tables): ?string
    {
        $problem = null;
        $code = rtrim(trim($this->stripLiterals($sql, $problem)), "; \t\n\r");

        if ($problem !== null) {
            return $problem;
        }
        if ($code === '') {
            return 'empty query';
        }
        if (str_contains($code, ';')) {
            return 'more than one statement';
        }
        if (! preg_match('/^\(*\s*(select|with)\b/i', $code)) {
            return 'only SELECT queries are allowed';
        }

        $lower = strtolower($code);

        if (preg_match('/\b('.implode('|', self::WRITE_KEYWORDS).')\b/', $lower, $match)) {
            return "write or admin keyword: {$match[1]}";
        }
        if (preg_match('/\bfor\s+(share|no\s+key\s+update|key\s+share)\b/', $lower)) {
            return 'row locking';
        }

        $functions = array_map(fn ($f) => preg_quote(strtolower((string) $f), '/'), array_merge(self::FUNCTIONS, (array) ($options['deny_functions'] ?? [])));
        if (preg_match('/\b('.implode('|', $functions).')\b/', $lower, $match)) {
            return "dangerous function: {$match[1]}";
        }

        if (! ($options['allow_system_tables'] ?? false)
            && (preg_match('/\b('.implode('|', self::SYSTEM_TABLES).')\b/', $lower, $match)
                || preg_match(self::SYSTEM_PREFIXES, $lower, $match)
                || preg_match('/\b(mysql|sys)\s*\./', $lower, $match))) {
            return "system table: {$match[1]}";
        }

        $tables = $this->tables($lower);
        $allowed = array_map(fn ($t) => strtolower((string) $t), (array) ($options['allowed_tables'] ?? []));

        foreach ($allowed === [] ? [] : $tables as $table) {
            if (! in_array($table, $allowed, true)) {
                return "table not allowed: {$table}";
            }
        }

        return null;
    }

    /**
     * Replace string literals with '' and drop comments, so keywords are only matched in code.
     * Quoted identifiers keep their name. Anything a database could read differently is reported.
     */
    private function stripLiterals(string $sql, ?string &$problem): string
    {
        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];
            $next = $sql[$i + 1] ?? '';

            if ($char === "'") {
                $end = $i + 1;
                while ($end < $length) {
                    if ($sql[$end] === "'" && ($sql[$end + 1] ?? '') === "'") {
                        $end += 2;

                        continue;
                    }
                    if ($sql[$end] === "'") {
                        break;
                    }
                    $end++;
                }

                $literal = substr($sql, $i, $end - $i + 1);
                // MySQL treats \' as an escape, PostgreSQL does not: the statement boundary is ambiguous
                if (str_contains($literal, '\\')) {
                    $problem = 'backslash escape in a string literal';
                }
                if ($end >= $length) {
                    $problem = 'unterminated string literal';
                }

                $out .= "''";
                $i = $end + 1;

                continue;
            }

            if ($char === '"' || $char === '`') {
                $end = strpos($sql, $char, $i + 1);
                if ($end === false) {
                    // Everything after would be swallowed here but executed by the database
                    $problem = 'unterminated quoted identifier';
                    $end = $length;
                }

                // The quotes themselves separate tokens: without a space FROM`secrets` would
                // fuse into "fromsecrets" and the table would not be seen at all
                $name = (string) preg_replace('/\W/', '_', substr($sql, $i + 1, $end - $i - 1));
                $out .= (preg_match('/\w$/', $out) === 1 ? ' ' : '').$name;
                $i = $end + 1;
                if (preg_match('/\A\w/', substr($sql, $i, 1)) === 1) {
                    $out .= ' ';
                }

                continue;
            }

            // MySQL only treats -- as a comment when whitespace follows; elsewhere "1--1" would hide code
            if ($char === '-' && $next === '-' && ($i + 2 >= $length || ctype_space($sql[$i + 2]))) {
                $end = strpos($sql, "\n", $i);
                $i = $end === false ? $length : $end;
                $out .= ' ';

                continue;
            }

            // MySQL reads # as a comment to end of line; PostgreSQL reads it as an operator
            if ($char === '#') {
                $problem = 'ambiguous "#" (a comment in MySQL, an operator in PostgreSQL)';
                $out .= ' ';
                $i++;

                continue;
            }

            if ($char === '/' && $next === '*') {
                // MySQL runs the contents of /*! ... */
                if (($sql[$i + 2] ?? '') === '!') {
                    $problem = 'executable comment';
                }
                $end = strpos($sql, '*/', $i + 2);
                $i = $end === false ? $length : $end + 2;
                $out .= ' ';

                continue;
            }

            if ($char === '$' && ($i === 0 || ! preg_match('/[\w$]/', $sql[$i - 1])) && preg_match('/\G\$([a-z_]\w*)?\$/i', $sql, $match, 0, $i)) {
                $end = strpos($sql, $match[0], $i + strlen($match[0]));
                if ($end === false) {
                    // Like an unterminated quote: everything after it is hidden here but read
                    // as code by a database that ends the literal differently
                    $problem = 'unterminated dollar-quoted string';
                }
                $i = $end === false ? $length : $end + strlen($match[0]);
                $out .= "''";

                continue;
            }

            $out .= $char;
            $i++;
        }

        return $out;
    }

    /**
     * Tables named after FROM and JOIN. A common table expression stands for itself only
     * after its own definition closes: in "WITH users AS (SELECT * FROM users)" the inner
     * reference is the real table.
     *
     * @return array<int, string>
     */
    private function tables(string $code): array
    {
        // EXTRACT(YEAR FROM x), SUBSTRING(s FROM 2), TRIM(... FROM s) are not table references
        $code = (string) preg_replace('/\b(extract|substring|trim|overlay|position)\s*\([^()]*\)/', '0', $code);

        $ctes = $this->commonTableExpressions($code);

        $identifier = '(?:[a-z_][\w$]*\.)?[a-z_][\w$]*';

        // "FROM (users)", "FROM ((users))" and "FROM a, (users)" are table references, not
        // subqueries: take the parentheses off a bare name so it is seen. A parenthesis holding
        // a SELECT never matches. The replacement keeps the string length, so the offsets the
        // common table expressions were recorded at still line up.
        for ($pass = 0; $pass < 8; $pass++) {
            $unwrapped = preg_replace_callback(
                "/\\(\\s*({$identifier})\\s*\\)/",
                fn (array $m) => str_pad(' '.$m[1].' ', strlen($m[0])),
                $code,
                -1,
                $count
            );

            $code = (string) $unwrapped;

            if ($count === 0) {
                break;
            }
        }
        // An alias is never a keyword — otherwise "FROM a JOIN b" would read JOIN as a's alias and miss b
        $alias = '(?:\s+(?:as\s+)?(?!(?:join|inner|left|right|full|cross|natural|outer|straight_join|lateral|where|on|using|group|order|limit|offset|fetch|having|window|union|except|intersect|minus|for|qualify)\b)[a-z_]\w*)?';
        // straight_join is listed first: \bjoin cannot match inside it, the underscore is a word character
        preg_match_all("/\\b(?:straight_join|from|join)\\s+({$identifier}{$alias}(?:\\s*,\\s*{$identifier}{$alias})*)/", $code, $matches, PREG_OFFSET_CAPTURE);

        $tables = [];

        foreach ($matches[1] as [$list, $offset]) {
            foreach (explode(',', $list) as $part) {
                $name = (string) strtok(trim($part), " \t\n\r");

                if ($name === '' || (isset($ctes[$name]) && $offset > $ctes[$name])) {
                    continue;
                }

                $tables[] = $name;
            }
        }

        return array_values(array_unique($tables));
    }

    /**
     * Names declared in a leading WITH list, each mapped to the offset where its body ends.
     * Only that list counts: "SELECT … WINDOW w AS (), users AS ()" declares no tables.
     *
     * @return array<string, int>
     */
    private function commonTableExpressions(string $code): array
    {
        if (! preg_match('/^\(*\s*with\s+(?:recursive\s+)?/i', $code, $start)) {
            return [];
        }

        $ctes = [];
        $offset = strlen($start[0]);
        $length = strlen($code);

        while ($offset < $length) {
            if (! preg_match('/\G\s*([a-z_]\w*)\s*(?:\([^()]*\)\s*)?as\s*(?:not\s+)?(?:materialized\s+)?\(/i', $code, $match, 0, $offset)) {
                break;
            }

            $end = $this->matchingParenthesis($code, $offset + strlen($match[0]) - 1);
            if ($end === null) {
                break;
            }

            $ctes[strtolower($match[1])] = $end;

            if (! preg_match('/\G\s*,/', $code, $comma, 0, $end + 1)) {
                break;
            }

            $offset = $end + 1 + strlen($comma[0]);
        }

        return $ctes;
    }

    private function matchingParenthesis(string $code, int $open): ?int
    {
        $depth = 0;

        for ($i = $open, $length = strlen($code); $i < $length; $i++) {
            if ($code[$i] === '(') {
                $depth++;
            } elseif ($code[$i] === ')' && --$depth === 0) {
                return $i;
            }
        }

        return null;
    }
}
