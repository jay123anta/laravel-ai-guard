<?php

namespace JayAnta\AiGuard\Support;

/**
 * The JSON Schema subset that tool definitions use: type, enum, const, string
 * length/pattern/format, numeric bounds, array items, object properties,
 * required, additionalProperties, and the allOf/anyOf/oneOf/not combinators.
 * Returns human-readable errors.
 *
 * A schema is a security policy here, so a keyword this validator does not implement is an
 * error rather than something quietly ignored — a constraint that is silently dropped is a
 * tool argument nobody is checking.
 */
class JsonSchemaValidator
{
    private const SUPPORTED = [
        'type', 'enum', 'const', 'allOf', 'anyOf', 'oneOf', 'not',
        'minLength', 'maxLength', 'pattern', 'format',
        'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
        'minItems', 'maxItems', 'uniqueItems', 'items',
        'properties', 'required', 'additionalProperties', 'minProperties', 'maxProperties',
        // Annotations, which constrain nothing
        'title', 'description', 'default', 'examples', 'deprecated', 'readOnly', 'writeOnly',
        '$schema', '$id', '$comment', 'nullable',
    ];

    private const NUMERIC_KEYWORDS = [
        'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
        'minLength', 'maxLength', 'minItems', 'maxItems', 'minProperties', 'maxProperties',
    ];

    /**
     * @return array<int, string>
     */
    public static function validate(mixed $value, array $schema, string $path = '$'): array
    {
        $errors = [];

        // A pattern that does not compile is checked once for the whole schema, before anything
        // is evaluated: inside `not` a pattern that silently never matches would invert into a
        // rule that accepts everything
        if ($path === '$') {
            $broken = self::uncompilablePatterns($schema, $path);

            if ($broken !== []) {
                return $broken;
            }
        }

        foreach (array_keys($schema) as $keyword) {
            if (! in_array((string) $keyword, self::SUPPORTED, true)) {
                $errors[] = "{$path} cannot be checked: the schema uses ".(string) $keyword;
            }
        }

        // A bound PHP cannot compare as a number is a rule nobody is checking: any array compares
        // greater than any number, so maximum: [10] would never fail
        foreach (self::NUMERIC_KEYWORDS as $keyword) {
            if (array_key_exists($keyword, $schema) && ! is_int($schema[$keyword]) && ! is_float($schema[$keyword])) {
                $errors[] = "{$path} cannot be checked: {$keyword} is not a number";
            }
        }

        if ($errors !== []) {
            return $errors;
        }

        if (isset($schema['type']) && ! self::matchesType($value, (array) $schema['type'])) {
            return ["{$path} must be ".implode(' or ', (array) $schema['type'])];
        }

        array_push($errors, ...self::validateCombinators($value, $schema, $path));

        if (array_key_exists('const', $schema) && $value !== $schema['const']) {
            $errors[] = "{$path} must be ".json_encode($schema['const']);
        }

        if (isset($schema['enum']) && is_array($schema['enum']) && ! in_array($value, $schema['enum'], true)) {
            $errors[] = "{$path} must be one of ".implode(', ', array_map(fn ($v) => (string) json_encode($v), $schema['enum']));
        }

        if (is_string($value)) {
            array_push($errors, ...self::validateString($value, $schema, $path));
        } elseif (is_int($value) || is_float($value)) {
            array_push($errors, ...self::validateNumber($value, $schema, $path));
        } elseif ($value === []) {
            // [] is both an empty list and an empty object, so both sets of rules apply to it
            if (self::isArraySchema($schema)) {
                array_push($errors, ...self::validateArray($value, $schema, $path));
            }
            array_push($errors, ...self::validateObject($value, $schema, $path));
        } elseif (is_array($value) && array_is_list($value) && self::isArraySchema($schema)) {
            array_push($errors, ...self::validateArray($value, $schema, $path));
        } elseif (is_array($value)) {
            array_push($errors, ...self::validateObject($value, $schema, $path));
        }

        return $errors;
    }

    /**
     * Does this schema describe an array? "type" may be a list ("type": ["array", "null"]), and
     * a schema carrying only array keywords still constrains one — comparing type === 'array'
     * alone would drop minItems/maxItems/uniqueItems without a word.
     */
    private static function isArraySchema(array $schema): bool
    {
        if (in_array('array', (array) ($schema['type'] ?? []), true)) {
            return true;
        }

        return isset($schema['items']) || isset($schema['minItems']) || isset($schema['maxItems']) || isset($schema['uniqueItems']);
    }

    /**
     * Every `pattern` in the schema tree that PCRE will not accept.
     *
     * @return array<int, string>
     */
    private static function uncompilablePatterns(array $schema, string $path): array
    {
        $errors = [];

        if (isset($schema['pattern']) && is_string($schema['pattern']) && @preg_match(self::compile($schema['pattern']), '') === false) {
            $errors[] = "{$path} cannot be checked: the pattern does not compile";
        }

        foreach (['properties', 'allOf', 'anyOf', 'oneOf'] as $keyword) {
            foreach ((array) ($schema[$keyword] ?? []) as $key => $sub) {
                if (is_array($sub)) {
                    array_push($errors, ...self::uncompilablePatterns($sub, $keyword === 'properties' ? "{$path}.{$key}" : $path));
                }
            }
        }

        foreach (['items', 'not', 'additionalProperties'] as $keyword) {
            if (is_array($schema[$keyword] ?? null)) {
                array_push($errors, ...self::uncompilablePatterns($schema[$keyword], $keyword === 'items' ? "{$path}[]" : $path));
            }
        }

        return $errors;
    }

    /**
     * A JSON Schema pattern as a PCRE. Only delimiters the author has not escaped are escaped,
     * so an already-escaped "^\/tmp\/" still compiles.
     */
    private static function compile(string $pattern): string
    {
        return '/'.preg_replace('#(?<!\\\\)/#', '\\/', $pattern).'/u';
    }

    /**
     * allOf / anyOf / oneOf / not.
     *
     * @return array<int, string>
     */
    private static function validateCombinators(mixed $value, array $schema, string $path): array
    {
        $errors = [];

        foreach ((array) ($schema['allOf'] ?? []) as $subSchema) {
            if (is_array($subSchema)) {
                array_push($errors, ...self::validate($value, $subSchema, $path));
            }
        }

        foreach (['anyOf', 'oneOf'] as $keyword) {
            if (! isset($schema[$keyword]) || ! is_array($schema[$keyword])) {
                continue;
            }

            $passed = 0;
            foreach ($schema[$keyword] as $subSchema) {
                if (is_array($subSchema) && self::validate($value, $subSchema, $path) === []) {
                    $passed++;
                }
            }

            if ($passed === 0 || ($keyword === 'oneOf' && $passed > 1)) {
                $errors[] = "{$path} must match exactly ".($keyword === 'oneOf' ? 'one' : 'one or more')." of the {$keyword} schemas";
            }
        }

        if (isset($schema['not']) && is_array($schema['not']) && self::validate($value, $schema['not'], $path) === []) {
            $errors[] = "{$path} must not match the excluded schema";
        }

        return $errors;
    }

    /**
     * @param  array<int, string>  $types
     */
    private static function matchesType(mixed $value, array $types): bool
    {
        foreach ($types as $type) {
            $matches = match ($type) {
                'string' => is_string($value),
                'integer' => is_int($value),
                'number' => is_int($value) || is_float($value),
                'boolean' => is_bool($value),
                'null' => $value === null,
                'array' => is_array($value) && array_is_list($value),
                'object' => is_array($value) && ($value === [] || ! array_is_list($value)),
                default => false,
            };

            if ($matches) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, string>
     */
    private static function validateString(string $value, array $schema, string $path): array
    {
        $errors = [];
        $length = mb_strlen($value);

        if (isset($schema['minLength']) && $length < (int) $schema['minLength']) {
            $errors[] = "{$path} must be at least {$schema['minLength']} characters";
        }
        if (isset($schema['maxLength']) && $length > (int) $schema['maxLength']) {
            $errors[] = "{$path} must be at most {$schema['maxLength']} characters";
        }
        if (isset($schema['pattern']) && @preg_match(self::compile((string) $schema['pattern']), $value) !== 1) {
            $errors[] = "{$path} does not match the required pattern";
        }

        $format = $schema['format'] ?? null;
        $valid = match ($format) {
            'email' => filter_var($value, FILTER_VALIDATE_EMAIL) !== false,
            'uri', 'url' => filter_var($value, FILTER_VALIDATE_URL) !== false,
            'uuid' => preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $value) === 1,
            'date' => preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) === 1,
            default => true,
        };
        if (! $valid) {
            $errors[] = "{$path} must be a valid {$format}";
        }

        return $errors;
    }

    /**
     * @return array<int, string>
     */
    private static function validateNumber(int|float $value, array $schema, string $path): array
    {
        $errors = [];

        if (isset($schema['minimum']) && $value < $schema['minimum']) {
            $errors[] = "{$path} must be at least {$schema['minimum']}";
        }
        if (isset($schema['maximum']) && $value > $schema['maximum']) {
            $errors[] = "{$path} must be at most {$schema['maximum']}";
        }
        if (isset($schema['exclusiveMinimum']) && $value <= $schema['exclusiveMinimum']) {
            $errors[] = "{$path} must be greater than {$schema['exclusiveMinimum']}";
        }
        if (isset($schema['exclusiveMaximum']) && $value >= $schema['exclusiveMaximum']) {
            $errors[] = "{$path} must be less than {$schema['exclusiveMaximum']}";
        }
        if (isset($schema['multipleOf']) && is_numeric($schema['multipleOf']) && (float) $schema['multipleOf'] > 0
            && abs(fmod((float) $value, (float) $schema['multipleOf'])) > 1e-9) {
            $errors[] = "{$path} must be a multiple of {$schema['multipleOf']}";
        }

        return $errors;
    }

    /**
     * @param  array<int, mixed>  $value
     * @return array<int, string>
     */
    private static function validateArray(array $value, array $schema, string $path): array
    {
        $errors = [];

        if (isset($schema['minItems']) && count($value) < (int) $schema['minItems']) {
            $errors[] = "{$path} must have at least {$schema['minItems']} items";
        }
        if (isset($schema['maxItems']) && count($value) > (int) $schema['maxItems']) {
            $errors[] = "{$path} must have at most {$schema['maxItems']} items";
        }
        if (($schema['uniqueItems'] ?? false) === true && count($value) !== count(array_unique(array_map(
            fn ($item) => is_scalar($item) || $item === null ? gettype($item).':'.var_export($item, true) : CanonicalJson::encode($item),
            $value
        )))) {
            $errors[] = "{$path} must not contain duplicate items";
        }
        if (isset($schema['items']) && is_array($schema['items'])) {
            foreach ($value as $index => $item) {
                array_push($errors, ...self::validate($item, $schema['items'], "{$path}[{$index}]"));
            }
        }

        return $errors;
    }

    /**
     * @return array<int, string>
     */
    private static function validateObject(array $value, array $schema, string $path): array
    {
        $errors = [];
        $properties = (array) ($schema['properties'] ?? []);

        if (isset($schema['minProperties']) && count($value) < (int) $schema['minProperties']) {
            $errors[] = "{$path} must have at least {$schema['minProperties']} properties";
        }
        if (isset($schema['maxProperties']) && count($value) > (int) $schema['maxProperties']) {
            $errors[] = "{$path} must have at most {$schema['maxProperties']} properties";
        }

        foreach ((array) ($schema['required'] ?? []) as $required) {
            if (! array_key_exists($required, $value)) {
                $errors[] = "{$path}.{$required} is required";
            }
        }

        foreach ($value as $key => $item) {
            if (isset($properties[$key]) && is_array($properties[$key])) {
                array_push($errors, ...self::validate($item, $properties[$key], "{$path}.{$key}"));
            } elseif (($schema['additionalProperties'] ?? true) === false) {
                $errors[] = "{$path}.{$key} is not allowed";
            } elseif (is_array($schema['additionalProperties'] ?? null)) {
                array_push($errors, ...self::validate($item, $schema['additionalProperties'], "{$path}.{$key}"));
            }
        }

        return $errors;
    }
}
