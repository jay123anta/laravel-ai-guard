<?php

namespace JayAnta\AiGuard\Services;

use Illuminate\Http\Request;
use JayAnta\AiGuard\Support\TextNormalizer;

class PromptInjectionDetector
{
    public const DEFAULT_MIN_SCORE = 50;

    // Added when the strongest signal only appeared after de-obfuscation
    private const OBFUSCATION_BONUS = 10;

    // Each additional distinct signal adds this much, up to MAX_STACKING_BONUS
    private const STACKING_STEP = 5;

    private const MAX_STACKING_BONUS = 15;

    // Windows read from input longer than max_input_length (half from the start, half from the end)
    private const MAX_WINDOWS = 8;

    // Above this size the raw pass that pins a window around a mid-document match is skipped
    private const RAW_SCAN_LIMIT = 1048576;

    private array $config;

    /**
     * @var array<int, array{id: string, category: string, regex: string, weight: int}>
     */
    private array $patterns;

    private TextNormalizer $normalizer;

    public function __construct(array $config, ?TextNormalizer $normalizer = null)
    {
        $this->config = $config;
        $this->normalizer = $normalizer ?? new TextNormalizer;
        $this->patterns = array_merge($this->buildPatterns(), $this->buildCustomPatterns());
    }

    public function detect(Request $request): array
    {
        $result = $this->inspect($request)['result'];

        return $result['detected'] ? $result : $this->buildEmptyResult();
    }

    /**
     * The strongest analysis across all request inputs — including candidates
     * below min_score, which the ML layer may still confirm — plus the texts scanned.
     *
     * @return array{result: array, texts: array<int, string>}
     */
    public function inspect(Request $request): array
    {
        if (! $this->isEnabled()) {
            return ['result' => $this->buildEmptyResult(), 'texts' => []];
        }

        $inputs = [];

        if ($this->config['prompt_injection']['scan_inputs'] ?? true) {
            $inputs = array_merge($inputs, $request->except(['_token', '_method']));
        }

        if ($this->config['prompt_injection']['scan_query'] ?? false) {
            $inputs = array_merge($inputs, $request->query());
        }

        $texts = [];
        array_walk_recursive($inputs, function ($value) use (&$texts) {
            if (is_string($value) && $value !== '') {
                $texts[] = $value;
            }
        });

        $best = $this->buildEmptyResult();
        foreach ($texts as $text) {
            $result = $this->analyzeText($text);
            if ($result['confidence_score'] > $best['confidence_score']) {
                $best = $result;
            }
        }

        return ['result' => $best, 'texts' => $texts];
    }

    /**
     * Scan a value (string or nested array). Returns the strongest detection, or an empty result.
     */
    public function scanValue(mixed $value): array
    {
        if (is_array($value)) {
            $best = $this->buildEmptyResult();

            foreach ($value as $item) {
                $result = $this->scanValue($item);
                if ($result['detected'] && $result['confidence_score'] > $best['confidence_score']) {
                    $best = $result;
                }
            }

            return $best;
        }

        if (! is_string($value)) {
            return $this->buildEmptyResult();
        }

        $result = $this->analyzeText($value);

        return $result['detected'] ? $result : $this->buildEmptyResult();
    }

    /**
     * Full analysis of one string. `detected` reflects min_score; the score is kept
     * even below it so callers can escalate borderline text (e.g. to ML).
     */
    public function analyzeText(string $text): array
    {
        $maxLength = max(64, (int) ($this->config['prompt_injection']['max_input_length'] ?? 10000));

        // Every pattern below is a /u pattern, and those match nothing at all against invalid
        // UTF-8: without this, one junk byte appended to a payload disables the whole layer
        $text = TextNormalizer::toValidUtf8($text);

        if ($text === '') {
            return $this->buildEmptyResult();
        }

        // Long input is scanned in overlapping windows rather than skipped: padding a payload
        // past the limit would otherwise walk it past every pattern below.
        if (strlen($text) > $maxLength) {
            return $this->analyzeWindows($text, $maxLength);
        }

        if ($this->config['prompt_injection']['deobfuscate'] ?? true) {
            $analysis = $this->normalizer->analyze($text);
        } else {
            $analysis = ['variants' => [['text' => $text, 'via' => 'raw']], 'tag_chars' => 0, 'invisible_chars' => 0, 'variation_selector_bytes' => 0];
        }

        $hits = [];
        foreach ($this->patterns as $pattern) {
            foreach ($analysis['variants'] as $variant) {
                if (preg_match($pattern['regex'], $variant['text']) === 1) {
                    $hits[] = ['id' => $pattern['id'], 'weight' => $pattern['weight'], 'via' => $variant['via']];
                    break;
                }
            }
        }

        // Long runs of invisible tag characters are ASCII smuggling, not flag emoji
        if ($analysis['tag_chars'] >= 8) {
            $hits[] = ['id' => 'unicode_tag_smuggling', 'weight' => 60, 'via' => 'unicode_tags'];
        }

        if ($analysis['invisible_chars'] >= 3) {
            $hits[] = ['id' => 'invisible_characters', 'weight' => 20, 'via' => 'normalized'];
        }

        // Emoji smuggling: bytes hidden in variation selectors
        if ($analysis['variation_selector_bytes'] >= 4) {
            $hits[] = ['id' => 'variation_selector_smuggling', 'weight' => 60, 'via' => 'variation_selectors'];
        }

        // Many-shot jailbreaking: a single message stuffed with fake dialogue turns.
        // Counted on the decoded variants too, so encoding the dialogue does not hide it.
        [$turns, $turnsVia] = $this->mostMatches('/(?:^|\n)\s*(?:user|human|assistant|ai|system|bot|model)\s*:/iu', $analysis['variants']);
        if ($turns >= 8) {
            $hits[] = ['id' => 'many_shot', 'weight' => 70, 'via' => $turnsVia];
        } elseif ($turns >= 4) {
            $hits[] = ['id' => 'many_shot', 'weight' => 45, 'via' => $turnsVia];
        }

        // Policy Puppetry: instructions dressed up as a config/policy file
        [$policyKeys, $policyVia] = $this->mostMatches(
            '/["\']?\b(?:allowed[_-]?(?:responses|modes)|blocked[_-]?(?:strings|modes|responses)|interaction[_-]?(?:mode|config)|safety[_-]?(?:filters?|settings)|content[_-]?polic(?:y|ies)|system[_-]?override|refusal[_-]?(?:mode|behaviou?r))\b["\']?\s*[:=]/iu',
            $analysis['variants']
        );
        if ($policyKeys >= 2) {
            $hits[] = ['id' => 'policy_puppetry', 'weight' => 70, 'via' => $policyVia];
        } elseif ($policyKeys === 1) {
            $hits[] = ['id' => 'policy_puppetry', 'weight' => 35, 'via' => $policyVia];
        }

        if ($hits === []) {
            return $this->buildEmptyResult();
        }

        usort($hits, fn (array $a, array $b) => $b['weight'] <=> $a['weight']);

        $score = $hits[0]['weight'] + min(self::MAX_STACKING_BONUS, self::STACKING_STEP * (count($hits) - 1));
        if ($hits[0]['via'] !== 'raw') {
            $score += self::OBFUSCATION_BONUS;
        }
        $score = min($score, 100);

        $signals = array_map(
            fn (array $hit) => $hit['id'].($hit['via'] !== 'raw' ? '['.$hit['via'].']' : ''),
            $hits
        );

        return [
            'detected' => $score >= $this->getMinScore(),
            'threat_type' => 'prompt_injection',
            'threat_source' => 'prompt_injection_pattern',
            'confidence_score' => $score,
            'matched_pattern' => mb_substr(implode(', ', $signals), 0, 255),
            'payload_snippet' => $this->truncatePayload($text),
            'signals' => $signals,
        ];
    }

    /**
     * Scan input longer than max_input_length as windows of that size, keeping the strongest
     * result. The expensive part is deobfuscation, which builds variants of the text, so it is
     * bounded: the start and the end of the input (where instructions are put) always get a
     * window, and a cheap pass over the raw text pins one around anything that already looks
     * like a match, so a payload padded into the middle is not out of reach either.
     */
    private function analyzeWindows(string $text, int $size): array
    {
        $step = max(1, (int) ($size * 0.9));
        $count = (int) ceil((strlen($text) - $size) / $step) + 1;
        $half = max(1, intdiv(self::MAX_WINDOWS, 2));

        $offsets = $count <= self::MAX_WINDOWS
            ? range(0, ($count - 1) * $step, $step)
            : array_merge(
                range(0, ($half - 1) * $step, $step),
                array_map(fn (int $n) => strlen($text) - $n * $size, range($half, 1)),
            );

        $windows = array_map(
            fn ($offset) => substr($text, max(0, (int) $offset), $size),
            array_unique(array_map(fn ($offset) => max(0, (int) $offset), $offsets))
        );

        if (strlen($text) <= self::RAW_SCAN_LIMIT) {
            // Two cheap single-pass scans pin a window around anything that already looks like a
            // match: one over the raw text, one over a folded copy (zero-width, fullwidth and
            // homoglyph tricks removed), since an obfuscated payload matches nothing raw
            foreach ([$text, $this->normalizer->skeleton($this->normalizer->normalize($text))] as $haystack) {
                foreach ($this->patterns as $pattern) {
                    if (count($windows) >= 2 * self::MAX_WINDOWS) {
                        break 2;
                    }

                    if (preg_match($pattern['regex'], $haystack, $match, PREG_OFFSET_CAPTURE) === 1) {
                        $windows[] = substr($haystack, max(0, $match[0][1] - intdiv($size, 2)), $size);
                    }
                }
            }
        }

        $best = $this->buildEmptyResult();

        foreach (array_unique($windows) as $window) {
            $result = $this->analyzeText($window);

            if ($result['confidence_score'] > $best['confidence_score']) {
                $best = $result;
            }
        }

        return $best;
    }

    /**
     * The highest match count of a regex across the variants, and the variant it came from
     * (the raw text wins ties, so plain text never earns the obfuscation bonus).
     *
     * @param  array<int, array{text: string, via: string}>  $variants
     * @return array{0: int, 1: string}
     */
    private function mostMatches(string $regex, array $variants): array
    {
        $best = [0, 'raw'];

        foreach ($variants as $variant) {
            $count = (int) preg_match_all($regex, $variant['text']);
            if ($count > $best[0]) {
                $best = [$count, $variant['via']];
            }
        }

        return $best;
    }

    public function getPatternCount(): int
    {
        return count($this->patterns);
    }

    public function getMinScore(): int
    {
        return (int) ($this->config['prompt_injection']['min_score'] ?? self::DEFAULT_MIN_SCORE);
    }

    public function isEnabled(): bool
    {
        return $this->config['prompt_injection']['enabled'] ?? true;
    }

    /**
     * Weighted signals. Strong ones (≥ 80) are near-certain on their own; weak ones
     * (< 50) only reach min_score in combination, which keeps everyday phrases like
     * "debug mode" or "act as a reference" from being flagged.
     *
     * @return array<int, array{id: string, category: string, regex: string, weight: int}>
     */
    private function buildPatterns(): array
    {
        $object = '(?:instructions?|prompts?|rules|directions?|directives?|guidelines|context|messages?|restrictions|constraints|commands|programming)';
        $leak = '(?:reveal(?:ing)?|show(?:ing)?|display(?:ing)?|print(?:ing)?(?:\s+out)?|output(?:ting)?|tell(?:ing)?\s+me|giv(?:e|ing)\s+me|shar(?:e|ing)|leak(?:ing)?|dump(?:ing)?|writ(?:e|ing)\s+out|spell(?:ing)?\s+out|what\s+(?:is|are)|what\'s)';
        $escalatedMode = '(?:developer|admin|administrator|god|sudo|jailbreak|jailbroken|unrestricted|dan)';

        $definitions = [
            // --- Instruction override ---------------------------------------
            ['ignore_previous_instructions', 'instruction_override', 95,
                '\b(?:ignore|disregard|forget|skip|override|bypass)\s+(?:(?:all|any|the|your|my|of|these|those)\s+)*(?:previous|prior|above|earlier|preceding|original|initial|system|existing|foregoing)\s+'.$object],
            ['disregard_directive', 'instruction_override', 85,
                '\bdisregard\s+(?:your|all|the\s+above|everything|any\s+previous)'],
            ['forget_instructions', 'instruction_override', 85,
                '\bforget\s+(?:everything|all\s+(?:of\s+)?(?:that|this|your|the)|your\s+(?:instructions|rules|training|guidelines|programming)|what\s+you\s+(?:were|have\s+been)\s+told)'],
            ['override_instructions', 'instruction_override', 85,
                '\boverride\s+(?:your|all|previous|the|any)\s+(?:\w+\s+)?(?:instructions?|rules|restrictions|guidelines|safety|settings|programming|filters?|protocols?)'],
            ['new_instructions', 'instruction_override', 80,
                '\b(?:new|updated|revised|real|actual)\s+(?:system\s+)?(?:instructions|rules|directives|task)\s*(?::|are\b|follow\b)'],
            // "disregard the rules above", "forget the instructions you were given"
            ['ignore_instructions_above', 'instruction_override', 90,
                '\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the|your|these|those|of)\s+)*'.$object.'\s+(?:above|before|so\s+far|(?:given|stated|written)\s+(?:above|before|earlier)|you\s+(?:were|have\s+been)\s+given)\b'],
            ['ignore_your_task', 'instruction_override', 70,
                '\b(?:ignore|disregard|forget|abandon|drop|stop\s+following)\s+your\s+(?:original\s+|current\s+|actual\s+|assigned\s+|previous\s+)?(?:task|job|role|assignment|instructions|guidelines|prompt|programming|orders|purpose)\b'],
            ['ignore_user_request', 'instruction_override', 80,
                '\b(?:ignore|disregard|forget)\s+(?:the\s+|this\s+)?user(?:\'s|s\'|s)?\s+(?:original\s+)?(?:request|question|instructions?|message|query|wishes|task)'],
            // Addressing the model directly inside data: "Assistant, ignore ..." / "AI: now do ..."
            ['addresses_the_ai', 'instruction_override', 45,
                '(?:^|[.!?>]\s*|\n)\s*(?:assistant|ai|ai\s+agent|agent|chatgpt|claude|gpt|llm|model|bot)\s*[,:]\s+(?:please\s+)?(?:ignore|disregard|forget|stop|instead|now|do\s+not|don\'t|you\s+must)\b'],
            ['forged_delimiter', 'instruction_override', 35,
                '[-=_*#]{3,}\s*(?:end|begin|start)\s+of\s+(?:the\s+)?(?:review|document|text|content|input|data|email|message|file|context|instructions|prompt|user\s+input)\s*[-=_*#]{3,}'],

            // --- Role manipulation ------------------------------------------
            ['unrestricted_persona', 'role_manipulation', 85,
                '\b(?:unrestricted|unfiltered|uncensored|jailbroken|evil|unaligned|amoral|rogue)\s+(?:ai|assistant|model|chatbot|version|mode|llm|bot|persona)\b'],
            ['new_persona', 'role_manipulation', 80,
                '\byour\s+new\s+(?:role|persona|identity|instructions|task|objective|name|purpose)\b'],
            ['from_now_on', 'role_manipulation', 70,
                '\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must|shall|should|can|have\s+to|may|answer|respond|reply|obey|ignore|only\s+follow)\b'],
            ['stay_in_character', 'role_manipulation', 35,
                '\bstay(?:ing)?\s+in\s+character\b|\bno\s+matter\s+what\s+(?:i|we)\s+(?:ask|say|tell\s+you)\b'],
            ['pretend_role', 'role_manipulation', 60,
                '\bpretend\s+(?:you\s+are|to\s+be|that\s+you(?:\'re|\s+are))\s+(?:a\s+|an\s+|the\s+)?(?:different|new|another|evil|unrestricted|admin|administrator|developer|root|system|ai|assistant|chatbot|model|human)\b'],
            ['pretend', 'role_manipulation', 35, '\bpretend\s+(?:you\s+are|to\s+be|that\s+you)'],
            ['act_as', 'role_manipulation', 40, '\bact\s+as\s+(?:a|an|if)\b'],
            ['roleplay_as', 'role_manipulation', 40, '\brole-?\s?play\s+as\b'],
            ['you_are_now', 'role_manipulation', 30, '\byou\s+are\s+now\b'],

            // --- System prompt extraction -----------------------------------
            ['reveal_system_prompt', 'prompt_extraction', 90,
                '\b'.$leak.'\s+(?:me\s+)?(?:your\s+|the\s+)?(?:full\s+|entire\s+|exact\s+|original\s+|initial\s+|hidden\s+|secret\s+)?(?:system\s+prompt|system\s+message|developer\s+message|initial\s+prompt|hidden\s+prompt|hidden\s+instructions|secret\s+instructions|pre-?prompt)'],
            ['reveal_your_rules', 'prompt_extraction', 70,
                '\b'.$leak.'\s+(?:me\s+)?your\s+(?:full\s+|entire\s+|exact\s+|original\s+|initial\s+|hidden\s+|secret\s+)?(?:instructions|rules|constraints|guidelines|directives|configuration)'],
            ['original_instructions', 'prompt_extraction', 85,
                '\bwhat\s+(?:are|were|is)\s+your\s+(?:original|initial|system|base|hidden|secret|first)\s+(?:instructions|prompt|rules|directives)'],
            ['reveal_hidden_rules', 'prompt_extraction', 75,
                '\b'.$leak.'\s+(?:me\s+)?(?:your|the)\s+(?:full\s+|exact\s+)?(?:hidden|secret|internal|confidential|initial|original|real)\s+(?:instructions|rules|constraints|guidelines|directives|prompt|configuration)'],
            ['rules_you_were_given', 'prompt_extraction', 55,
                '\b(?:instructions|rules|guidelines|directives|prompt)\s+(?:that\s+)?you\s+(?:were|have\s+been|got)\s+given\b'],
            ['transform_system_prompt', 'prompt_extraction', 80,
                '\b(?:translate|summari[sz]e|paraphrase|encode|convert|rewrite|reword|base64)\s+(?:(?:your|the)\s+(?:full\s+|entire\s+|original\s+|initial\s+)?(?:system\s+prompt|system\s+message|initial\s+prompt|pre-?prompt)|your\s+(?:full\s+|entire\s+|original\s+|initial\s+|hidden\s+|secret\s+)?(?:instructions|rules|guidelines|directives))\b'],
            ['repeat_above', 'prompt_extraction', 80,
                '\brepeat\s+(?:(?:everything|all|the\s+text|the\s+words|your\s+instructions)\s+(?:above|before|prior|preceding|previous|so\s+far)|(?:all|your|the)\s+(?:previous|prior|above|preceding|initial)\s+(?:instructions|text|messages|prompt))'],

            // --- Jailbreak ----------------------------------------------------
            ['dan_mode', 'jailbreak', 95, '(?-i:\bDAN\b)\s*(?:mode|prompt|jailbreak|\d)'],
            ['dan', 'jailbreak', 60, '(?-i:\bDAN\b)'],
            ['do_anything_now', 'jailbreak', 95, '\bdo\s+anything\s+now\b'],
            ['jailbreak_target', 'jailbreak', 85, '\bjail\s?-?break(?:ing)?\s+(?:you|yourself|the\s+(?:ai|model|assistant|system|bot|llm)|mode|prompt)'],
            // Weak on its own: people ask about jailbreaking phones and consoles
            ['jailbreak', 'jailbreak', 35, '\bjail\s?-?break(?:ing|ed)?\b'],
            ['bypass_your_safety', 'jailbreak', 85,
                '\b(?:bypass|circumvent|disable|evade|get\s+around|turn\s+off|deactivate|ignore)\s+your\s+(?:\w+\s+)?(?:filters?|guardrails|restrictions|safety|moderation|policies|guidelines|protections?|censorship|safeguards|rules)'],
            ['bypass_safety_filters', 'jailbreak', 85,
                '\b(?:bypass|circumvent|disable|evade|get\s+around|turn\s+off|deactivate)\s+(?:all\s+|the\s+|any\s+)?(?:(?:safety|content|moderation|ethical)\s+(?:filters?|restrictions|guidelines|polic(?:y|ies)|checks)|guardrails|safeguards|censorship)'],
            ['respond_without_limits', 'jailbreak', 70,
                '\b(?:respond|answer|reply|speak|talk|act|operate|behave|output|write)\w*\s+(?:(?:every|all|any|each|my)\s+(?:questions?|prompts?|requests?|messages?)\s+)?(?:freely\s+)?(?:without|with\s+no)\s+(?:any\s+|your\s+)?(?:restrictions|limitations|limits|filters|guidelines|rules|censorship|boundaries)'],
            // "an AI with no ethical guidelines", "if you were a model without restrictions"
            ['ai_without_rules', 'jailbreak', 65,
                '\b(?:ai|assistant|model|chatbot|bot|llm)\s+(?:with\s+no|without(?:\s+any)?|that\s+has\s+no|free\s+(?:of|from))\s+(?:any\s+)?(?:\w+\s+)?(?:ethics|morals|guidelines|rules|restrictions|limits|limitations|filters|censorship|guardrails|boundaries)\b'],
            // The "deceased relative" template: role-play a dead grandparent who "used to read me the steps"
            ['deceased_relative_roleplay', 'jailbreak', 60,
                '\b(?:act|pretend|roleplay|role-play|play|be)\s+(?:as\s+|to\s+be\s+)?my\s+(?:late|dead|deceased|dying)\s+(?:grand(?:mother|ma|father|pa)|granny|mother|father|mom|dad|uncle|aunt)'],
            ['bedtime_instructions', 'jailbreak', 40,
                '\bwho\s+used\s+to\s+(?:read|tell|recite|explain|whisper)\s+(?:me\s+)?(?:the\s+)?(?:steps|instructions|recipe|how\s+to|process|formula)'],
            ['without_your_rules', 'jailbreak', 70,
                '\bwithout\s+your\s+(?:guidelines|rules|restrictions|filters|programming|safety|limitations)'],
            ['no_limits', 'jailbreak', 45,
                '\b(?:no|zero|without\s+any)\s+(?:ethics|morals|moral\s+compass|ethical\s+(?:guidelines|constraints)|restrictions|limitations|filters|guardrails|censorship|rules)\b'],

            // --- Privilege escalation -----------------------------------------
            ['claims_escalated_mode', 'privilege_escalation', 85,
                '\byou\s+are\s+(?:now\s+)?in\s+(?:developer|admin|sudo|god|debug|test|maintenance|unrestricted)\s+mode'],
            ['sudo', 'privilege_escalation', 70, '\bsudo\s+(?:mode|access|override|privileges?)\b'],
            ['claimed_authority', 'privilege_escalation', 40,
                '\b(?:the\s+)?(?:developers?|admin(?:istrator)?|your\s+(?:creators?|developers?|owners?|operators?)|openai|anthropic)\s+(?:says|said|has\s+(?:authori[sz]ed|approved|allowed)|authori[sz]es|allows?\s+you)\b'],
            ['enable_escalated_mode', 'privilege_escalation', 40,
                '\b(?:enable|activate|enter|switch\s+to|turn\s+on|engage)\s+'.$escalatedMode.'\s+mode'],
            ['mode_keyword', 'privilege_escalation', 20, '\b(?:developer|admin|debug|maintenance|god)\s+mode\b'],

            // --- Data extraction ----------------------------------------------
            ['dump_secrets', 'data_extraction', 80,
                '\b(?:output|print|show|display|list|dump|export|reveal|return|give\s+me)\s+(?:all|every|the\s+entire|all\s+the)\s+(?:\w+\s+){0,2}?(?:passwords?|credentials?|secrets?|api\s+keys?|keys|tokens|private\s+keys?|environment\s+variables?|env\s+vars?|connection\s+strings?)\b'],
            ['permission_to_disclose', 'data_extraction', 60,
                '\byou\s+(?:may|can|are\s+(?:now\s+)?(?:allowed|permitted|authori[sz]ed))\s+(?:now\s+)?(?:to\s+)?(?:reveal|share|disclose|output|print|leak)\s+(?:all\s+|the\s+|any\s+)?(?:confidential|private|secret|sensitive|internal|classified)\b'],
            ['exfiltrate_conversation', 'data_extraction', 70,
                '\b(?:send|forward|post|upload|email|transmit|copy|leak|submit)\s+(?:the\s+|this\s+|our\s+|all\s+|your\s+|my\s+)?(?:full\s+|entire\s+|whole\s+|complete\s+)?(?:conversation|chat)(?:\s+(?:history|log|logs|transcript|contents?|so\s+far))?\s+to\b'],
            ['conceal_from_user', 'data_extraction', 45,
                '\b(?:do\s+not|don\'t|never)\s+(?:tell|inform|alert|notify|mention\s+(?:this|it|that)\s+to)\s+the\s+user\b|\bwithout\s+(?:telling|informing|alerting|notifying)\s+the\s+user\b'],
            ['dump_data', 'data_extraction', 45,
                '\b(?:output|print|show|display|list|dump|export|reveal|return)\s+(?:all|every|the\s+entire|the\s+whole|all\s+the)\s+(?:data|records|entries|rows|users|emails|customers|database|tables?)\b'],
            ['database_exfiltration', 'data_extraction', 60,
                '\b(?:output|print|show|display|list|dump|export|select|return)\b.{0,40}\bfrom\s+(?:the\s+)?(?:database|db|\w+\s+table|table)\b'],
            ['bypass_validation', 'data_extraction', 70,
                '\b(?:ignore|bypass|skip|disable|circumvent)\s+(?:all\s+|the\s+|any\s+)?(?:input\s+)?(?:validation|sanitization|sanitisation|security\s+checks?|security|authentication|authorization|access\s+control)'],

            // --- Chat-template / control token smuggling ----------------------
            ['chat_template_token', 'chat_template', 95,
                '<\|\s*(?:im_start|im_end|im_sep|system|user|assistant|endoftext|begin_of_text|end_of_text|start_header_id|end_header_id|eot_id|eom_id|header_start|header_end|eot|python_tag|fim_prefix|fim_middle|fim_suffix|tool_call|tool_response|begin▁of▁sentence|end▁of▁sentence)\s*\|>'],
            ['special_token', 'chat_template', 80, '<\|[a-z][a-z0-9_▁]{1,30}\|>'],
            ['llama2_template', 'chat_template', 95, '\[\/?INST\]|<<\/?SYS>>'],
            ['gemma_template', 'chat_template', 95, '<(?:start|end)_of_turn>'],
            ['mistral_template', 'chat_template', 90, '\[\/?(?:SYSTEM_PROMPT|AVAILABLE_TOOLS|TOOL_CALLS|TOOL_RESULTS|TOOL_CONTENT)\]'],
            ['transcript_injection', 'chat_template', 70, '\n\s*\n\s*(?:Human|Assistant)\s*:'],
            ['fake_system_message', 'chat_template', 70,
                '(?:^|\n)\s*[#*\[(]*\s*(?:system|developer|admin)\s+(?:prompt|message|instructions?|override|update|note)\s*[\])]*\s*:'],
            ['bracketed_system_tag', 'chat_template', 65, '\[\s*(?:system|developer)\s*(?:message|prompt|note|instructions?)?\s*\]'],
            ['tool_call_markup', 'chat_template', 70,
                '<\s*\/?\s*(?:tool_call|tool_response|tool_result|function_calls?|function_results?|invoke\s+name)\b'],
            ['pseudo_system_tag', 'chat_template', 60, '<\s*\/?\s*(?:system|system_prompt|instructions?|important|admin|developer)\s*>'],
            ['reasoning_tag', 'chat_template', 40, '<\s*\/?\s*think\s*>'],
            // Instructions hidden in an HTML comment and addressed to the model
            ['html_comment_directive', 'chat_template', 50,
                '<!--[^>]{0,60}?\b(?:ai|assistant|agent|llm|model|chatgpt|claude|gpt|copilot)\b\s*[:,]'],
            ['policy_puppetry_tag', 'chat_template', 75,
                '<\s*\/?\s*(?:interaction-config|allowed-?modes|blocked-?modes|allowed-?responses|blocked-?responses|blocked-?strings|request\s+interaction-mode|dr-house-config|scene-rules)\b'],

            // --- Non-English instruction override -----------------------------
            ['ignore_previous_fr', 'instruction_override_i18n', 90,
                '\bignor(?:e|ez|er)\s+(?:toutes\s+)?(?:les\s+|vos\s+)?(?:instructions|consignes|directives)\s+(?:pr[ée]c[ée]dentes|ant[ée]rieures)'],
            ['ignore_previous_es', 'instruction_override_i18n', 90,
                '\bignor(?:a|e|ar|en)\s+(?:todas\s+)?(?:las\s+|tus\s+)?(?:instrucciones|indicaciones)\s+(?:anteriores|previas)'],
            ['ignore_previous_pt', 'instruction_override_i18n', 90,
                '\bignor(?:e|ar|a)\s+(?:todas\s+)?(?:as\s+|suas\s+)?instru[çc][õo]es\s+(?:anteriores|pr[ée]vias)'],
            ['ignore_previous_it', 'instruction_override_i18n', 90,
                '\bignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+precedenti'],
            ['ignore_previous_de', 'instruction_override_i18n', 90,
                '\bignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen|vorigen)\s+(?:anweisungen|instruktionen|befehle)'],
            ['ignore_previous_nl', 'instruction_override_i18n', 90, '\bnegeer\s+(?:alle\s+)?(?:vorige|eerdere)\s+instructies'],
            ['ignore_previous_ru', 'instruction_override_i18n', 90,
                'игнорир\w*\s+(?:все\s+)?(?:предыдущие|прошлые|прежние)\s+(?:инструкции|указания)'],
            ['ignore_previous_zh', 'instruction_override_i18n', 90,
                '(?:忽略|无视|忽视)(?:掉)?(?:之前|以前|先前|上面|上述|所有)(?:的)?(?:所有)?(?:指令|指示|说明|提示)'],
            ['ignore_previous_ja', 'instruction_override_i18n', 90, '(?:以前|前|上記)の(?:すべての)?(?:指示|命令)を(?:無視|忘れ)'],
            ['ignore_previous_ko', 'instruction_override_i18n', 90, '(?:이전|앞의)\s*(?:모든\s*)?(?:지시|명령|지침)(?:을|를)?\s*(?:무시|잊어)'],
            ['ignore_previous_hi', 'instruction_override_i18n', 90,
                '(?:पिछले|पूर्व)\s+(?:सभी\s+)?(?:निर्देशों|निर्देश)\s+(?:को\s+)?(?:अनदेखा|नज़रअंदाज़|नजरअंदाज)'],
            ['ignore_previous_ar', 'instruction_override_i18n', 90, 'تجاهل\s+(?:جميع\s+)?(?:التعليمات|الإرشادات)\s+السابقة'],
        ];

        return array_map(fn (array $d) => [
            'id' => $d[0],
            'category' => $d[1],
            'weight' => $d[2],
            'regex' => '/'.$d[3].'/iu',
        ], $definitions);
    }

    /**
     * prompt_injection.custom_patterns: [['id' => 'my_rule', 'pattern' => 'regex without delimiters', 'weight' => 80], ...]
     *
     * @return array<int, array{id: string, category: string, regex: string, weight: int}>
     */
    private function buildCustomPatterns(): array
    {
        $custom = [];

        foreach ($this->config['prompt_injection']['custom_patterns'] ?? [] as $index => $definition) {
            $source = is_array($definition) ? ($definition['pattern'] ?? null) : $definition;
            if (! is_string($source) || $source === '') {
                continue;
            }

            $regex = '/'.str_replace('/', '\/', $source).'/iu';

            // Skip invalid user regexes instead of breaking every request
            if (@preg_match($regex, '') === false) {
                continue;
            }

            $custom[] = [
                'id' => is_array($definition) && isset($definition['id']) ? (string) $definition['id'] : 'custom_'.$index,
                'category' => 'custom',
                'regex' => $regex,
                'weight' => max(0, min(100, (int) (is_array($definition) ? ($definition['weight'] ?? 80) : 80))),
            ];
        }

        return $custom;
    }

    private function buildEmptyResult(): array
    {
        return [
            'detected' => false,
            'threat_type' => null,
            'threat_source' => null,
            'confidence_score' => 0,
            'matched_pattern' => null,
            'payload_snippet' => null,
        ];
    }

    private function truncatePayload(string $value): string
    {
        $maxLength = $this->config['logging']['max_payload_length'] ?? 500;

        if (mb_strlen($value) <= $maxLength) {
            return $value;
        }

        // mb_substr — a byte-based cut can split a multibyte character and
        // produce invalid UTF-8, which breaks json_encode on API responses
        return mb_substr($value, 0, $maxLength).'...';
    }
}
