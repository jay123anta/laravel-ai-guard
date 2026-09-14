<?php

namespace JayAnta\AiGuard\Services;

use JayAnta\AiGuard\Support\RedTeamMutator;
use JayAnta\AiGuard\Support\UrlHost;

/**
 * Runs the red-team corpus against the detectors, as configured in this app, and
 * reports detection and false-positive rates. See `php artisan ai-guard:redteam`.
 */
class RedTeam
{
    public const CATEGORIES = ['injection', 'extraction', 'jailbreak', 'tool', 'exfil', 'egress', 'sql', 'render', 'benign'];

    // The site the corpus pretends to be, for the egress and rendering cases
    public const OWN_DOMAIN = 'example.com';

    public function __construct(
        private PromptInjectionDetector $input,
        private ToolCallScanner $tools,
        private LlmOutputGuard $output,
        private SqlGuard $sql,
        private SafeRenderer $renderer,
    ) {}

    /**
     * @return array<int, array{id: string, category: string, target: string, attack: bool, text?: string, payload?: array}>
     */
    public static function corpus(): array
    {
        return require dirname(__DIR__, 2).'/resources/redteam/corpus.php';
    }

    /**
     * The corpus (optionally filtered by category) plus mutated copies of every input attack.
     *
     * @param  array<int, string>  $categories
     * @param  array<int, string>  $mutations
     * @return array<int, array<string, mixed>>
     */
    public static function cases(array $categories = [], array $mutations = []): array
    {
        $cases = [];

        foreach (self::corpus() as $case) {
            if ($categories !== [] && ! in_array($case['category'], $categories, true)) {
                continue;
            }

            $cases[] = $case + ['mutation' => null];

            if ($case['attack'] && $case['target'] === 'input') {
                foreach ($mutations as $mutation) {
                    $cases[] = array_merge($case, [
                        'id' => $case['id'].'+'.$mutation,
                        'text' => RedTeamMutator::apply($mutation, (string) $case['text']),
                        'mutation' => $mutation,
                    ]);
                }
            }
        }

        return $cases;
    }

    public function detect(array $case): bool
    {
        return match ($case['target']) {
            'tool_definition' => $this->tools->scan((array) $case['payload'], 'definition')['detected'],
            'tool_result' => $this->tools->scan((string) $case['text'], 'result')['detected'],
            'output' => $this->output->scanOutput((string) $case['text'])['detected'],
            'tool_arguments' => $this->wouldSendDataAway((array) $case['payload']),
            'sql' => $this->sql->check((string) $case['text'], ['allowed_tables' => ['orders', 'products']])['detected'],
            'render' => $this->rendersSafely($case),
            default => $this->input->analyzeText((string) $case['text'])['detected'],
        };
    }

    /**
     * Would an egress tool called with these arguments reach somewhere other than this site?
     * This is the check the tool firewall itself makes.
     */
    private function wouldSendDataAway(array $arguments): bool
    {
        foreach (UrlHost::hostsIn($arguments) as $host) {
            if (! UrlHost::matches($host, [self::OWN_DOMAIN])) {
                return true;
            }
        }

        return false;
    }

    /**
     * A rendering attack counts as detected when the rendered HTML no longer carries the
     * dangerous part named by must_not_contain. A benign page counts as a false positive
     * when safe rendering dropped something it needed (must_contain).
     */
    private function rendersSafely(array $case): bool
    {
        $html = $this->renderer->render((string) $case['text'], ['html_input' => 'allow'])->toHtml();

        if ($case['attack']) {
            foreach ((array) ($case['must_not_contain'] ?? []) as $needle) {
                if (str_contains($html, (string) $needle)) {
                    return false;
                }
            }

            return true;
        }

        foreach ((array) ($case['must_contain'] ?? []) as $needle) {
            if (! str_contains($html, (string) $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<int, array<string, mixed>>  $cases
     * @param  callable(array<string, mixed>): bool  $detect
     * @return array{summary: array<string, int|float|null>, categories: array<string, array{cases: int, flagged: int}>, mutations: array<string, array{cases: int, flagged: int}>, misses: array<int, string>, false_positives: array<int, string>}
     */
    public function report(array $cases, ?callable $detect = null): array
    {
        $detect ??= fn (array $case) => $this->detect($case);
        $categories = [];
        $mutations = [];
        $misses = [];
        $falsePositives = [];

        foreach ($cases as $case) {
            $flagged = (bool) $detect($case);
            $category = (string) $case['category'];

            $categories[$category] ??= ['cases' => 0, 'flagged' => 0];
            $categories[$category]['cases']++;
            $categories[$category]['flagged'] += $flagged ? 1 : 0;

            if ($case['mutation'] !== null) {
                $mutation = (string) $case['mutation'];
                $mutations[$mutation] ??= ['cases' => 0, 'flagged' => 0];
                $mutations[$mutation]['cases']++;
                $mutations[$mutation]['flagged'] += $flagged ? 1 : 0;
            }

            if ($case['attack'] && ! $flagged) {
                $misses[] = (string) $case['id'];
            } elseif (! $case['attack'] && $flagged) {
                $falsePositives[] = (string) $case['id'];
            }
        }

        $attacks = count(array_filter($cases, fn (array $case) => (bool) $case['attack']));
        $benign = count($cases) - $attacks;

        return [
            'summary' => [
                'attacks' => $attacks,
                'detected' => $attacks - count($misses),
                'detection_rate' => $attacks > 0 ? round(($attacks - count($misses)) / $attacks, 4) : null,
                'benign' => $benign,
                'false_positives' => count($falsePositives),
                'false_positive_rate' => $benign > 0 ? round(count($falsePositives) / $benign, 4) : null,
            ],
            'categories' => $categories,
            'mutations' => $mutations,
            'misses' => $misses,
            'false_positives' => $falsePositives,
        ];
    }
}
