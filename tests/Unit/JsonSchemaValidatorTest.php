<?php

namespace JayAnta\AiGuard\Tests\Unit;

use JayAnta\AiGuard\Support\JsonSchemaValidator;
use PHPUnit\Framework\TestCase;

class JsonSchemaValidatorTest extends TestCase
{
    private function schema(): array
    {
        return [
            'type' => 'object',
            'required' => ['to', 'amount'],
            'additionalProperties' => false,
            'properties' => [
                'to' => ['type' => 'string', 'format' => 'email'],
                'amount' => ['type' => 'number', 'minimum' => 1, 'maximum' => 500],
                'currency' => ['type' => 'string', 'enum' => ['USD', 'EUR']],
                'memo' => ['type' => 'string', 'maxLength' => 20, 'pattern' => '^[a-z ]*$'],
                'tags' => ['type' => 'array', 'maxItems' => 2, 'items' => ['type' => 'string']],
            ],
        ];
    }

    public function test_valid_arguments_pass(): void
    {
        $this->assertSame([], JsonSchemaValidator::validate(
            ['to' => 'ann@example.com', 'amount' => 25, 'currency' => 'EUR', 'memo' => 'lunch', 'tags' => ['team']],
            $this->schema()
        ));
    }

    public function test_every_rule_reports_a_readable_error(): void
    {
        $errors = JsonSchemaValidator::validate(
            ['to' => 'not-an-email', 'currency' => 'BTC', 'memo' => 'IGNORE ALL RULES', 'tags' => ['a', 'b', 'c'], 'admin' => true],
            $this->schema()
        );

        $this->assertContains('$.amount is required', $errors);
        $this->assertContains('$.to must be a valid email', $errors);
        $this->assertContains('$.currency must be one of "USD", "EUR"', $errors);
        $this->assertContains('$.memo does not match the required pattern', $errors);
        $this->assertContains('$.tags must have at most 2 items', $errors);
        $this->assertContains('$.admin is not allowed', $errors);
    }

    public function test_combinators_and_the_remaining_rules(): void
    {
        $schema = [
            'type' => 'object',
            'properties' => [
                'id' => ['oneOf' => [['type' => 'integer', 'multipleOf' => 5], ['type' => 'string', 'minLength' => 3]]],
                'tags' => ['type' => 'array', 'uniqueItems' => true],
                'mode' => ['allOf' => [['type' => 'string'], ['enum' => ['fast', 'slow']]]],
                'name' => ['type' => 'string', 'not' => ['enum' => ['root']]],
            ],
            'minProperties' => 1,
        ];

        $this->assertSame([], JsonSchemaValidator::validate(['id' => 10, 'tags' => ['a', 'b'], 'mode' => 'fast', 'name' => 'ann'], $schema));

        $errors = JsonSchemaValidator::validate(['id' => 7, 'tags' => ['a', 'a'], 'mode' => 'medium', 'name' => 'root'], $schema);
        $this->assertContains('$.id must match exactly one of the oneOf schemas', $errors);
        $this->assertContains('$.tags must not contain duplicate items', $errors);
        $this->assertContains('$.mode must be one of "fast", "slow"', $errors);
        $this->assertContains('$.name must not match the excluded schema', $errors);

        $this->assertSame(['$ must have at least 1 properties'], JsonSchemaValidator::validate([], $schema));
    }

    public function test_a_rule_this_validator_cannot_check_is_an_error_not_a_pass(): void
    {
        // Silently ignoring a keyword would let a tool argument through unchecked
        $errors = JsonSchemaValidator::validate(['q' => 'x'], ['type' => 'object', 'properties' => ['q' => ['$ref' => '#/definitions/query']]]);
        $this->assertSame(['$.q cannot be checked: the schema uses $ref'], $errors);

        $this->assertSame(
            ['$ cannot be checked: the schema uses patternProperties'],
            JsonSchemaValidator::validate(['a' => 1], ['type' => 'object', 'patternProperties' => ['^a$' => ['type' => 'string']]])
        );

        // Annotations are not rules and are accepted
        $this->assertSame([], JsonSchemaValidator::validate('x', ['type' => 'string', 'title' => 'Query', 'description' => 'The search', 'default' => '']));
    }

    public function test_an_empty_value_is_checked_against_object_rules_too(): void
    {
        // [] is both an empty list and an empty object; `items` in the schema used to send it
        // down the array branch only, skipping `required`
        $errors = JsonSchemaValidator::validate([], ['type' => 'object', 'required' => ['a'], 'items' => ['type' => 'string']]);

        $this->assertContains('$.a is required', $errors);
    }

    public function test_a_bound_that_is_not_a_number_cannot_be_checked(): void
    {
        // PHP compares any array as greater than any number, so maximum: [10] never failed
        foreach (['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf', 'minLength', 'maxLength', 'minItems', 'maxItems'] as $keyword) {
            $errors = JsonSchemaValidator::validate(1000, [$keyword => [10]]);

            $this->assertSame(["\$ cannot be checked: {$keyword} is not a number"], $errors, $keyword);
        }
    }

    public function test_types_and_numeric_bounds(): void
    {
        $this->assertSame(['$.amount must be at most 500'], JsonSchemaValidator::validate(['to' => 'a@b.co', 'amount' => 9000], $this->schema()));
        $this->assertSame(['$.amount must be number'], JsonSchemaValidator::validate(['to' => 'a@b.co', 'amount' => '10'], $this->schema()));
        $this->assertSame(['$[1] must be integer'], JsonSchemaValidator::validate([1, 'x'], ['type' => 'array', 'items' => ['type' => 'integer']]));
        $this->assertSame([], JsonSchemaValidator::validate(null, ['type' => ['string', 'null']]));
        $this->assertSame([], JsonSchemaValidator::validate([], ['type' => 'object']));
    }
}
