<?php

namespace JayAnta\AiGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array detect(\Illuminate\Http\Request $request)
 * @method static bool isEnabled()
 * @method static string getMode()
 * @method static array getStats(int $hours = 24)
 * @method static \Illuminate\Support\Collection getTopThreats(int $limit = 10)
 * @method static \Illuminate\Database\Eloquent\Collection getRecentThreats(int $limit = 20)
 * @method static array getDetectorInfo()
 */
class AiGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'ai-guard';
    }
}
