<?php

namespace JayAnta\AiGuard\Tests\Support;

use JayAnta\AiGuard\Services\WebBotAuthVerifier;

/**
 * Signs requests the way a Web Bot Auth agent does (RFC 9421, Ed25519).
 */
class WebBotAuthSigner
{
    /**
     * @return array{0: string, 1: string} [secret key, public key]
     */
    public static function keypair(): array
    {
        $pair = sodium_crypto_sign_keypair();

        return [sodium_crypto_sign_secretkey($pair), sodium_crypto_sign_publickey($pair)];
    }

    public static function jwk(string $publicKey): array
    {
        return ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => WebBotAuthVerifier::base64UrlEncode($publicKey)];
    }

    public static function keyid(string $publicKey): string
    {
        return WebBotAuthVerifier::thumbprint(WebBotAuthVerifier::base64UrlEncode($publicKey));
    }

    /**
     * @param  array{created?: int, expires?: int, nonce?: string, label?: string, keyid?: string, agent_header?: string, components?: array<int, string>, target_uri?: string}  $options
     * @return array<string, string>
     */
    public static function headers(string $secretKey, string $publicKey, string $authority, string $agent = 'https://chatgpt.com', array $options = []): array
    {
        $created = $options['created'] ?? time();
        $expires = $options['expires'] ?? $created + 60;
        $label = $options['label'] ?? 'sig1';
        $keyid = $options['keyid'] ?? self::keyid($publicKey);
        $agentHeader = $options['agent_header'] ?? '"'.$agent.'"';
        $components = $options['components'] ?? ['@authority', 'signature-agent'];

        $params = ';created='.$created.';keyid="'.$keyid.'";alg="ed25519";expires='.$expires
            .(isset($options['nonce']) ? ';nonce="'.$options['nonce'].'"' : '')
            .';tag="web-bot-auth"';
        $inner = '('.implode(' ', array_map(fn (string $c) => '"'.$c.'"', $components)).')'.$params;

        $values = [
            '@authority' => $authority,
            '@target-uri' => $options['target_uri'] ?? 'http://'.$authority.'/page',
            'signature-agent' => $agentHeader,
        ];

        $base = '';
        foreach ($components as $component) {
            $base .= '"'.$component.'": '.$values[$component]."\n";
        }
        $base .= '"@signature-params": '.$inner;

        return [
            'Signature-Agent' => $agentHeader,
            'Signature-Input' => $label.'='.$inner,
            'Signature' => $label.'=:'.base64_encode(sodium_crypto_sign_detached($base, $secretKey)).':',
        ];
    }
}
