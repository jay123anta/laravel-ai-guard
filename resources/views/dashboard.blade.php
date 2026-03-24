<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Guard — Threat Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
</head>
<body class="bg-[#0f172a] text-slate-200 min-h-screen" x-data="{ init() { setInterval(() => location.reload(), 30000) } }" x-init="init()">

    <!-- Navbar -->
    <nav class="bg-slate-800 border-b border-slate-700 px-6 py-4">
        <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div>
                <h1 class="text-xl font-bold text-white">&#128737; AI Guard</h1>
                <p class="text-sm text-slate-400">Threat Dashboard</p>
            </div>
            <div>
                @php
                    $mode = config('ai-guard.mode', 'log_only');
                @endphp
                @if($mode === 'block')
                    <span class="rounded-full px-3 py-1 text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">Mode: Block</span>
                @elseif($mode === 'rate_limit')
                    <span class="rounded-full px-3 py-1 text-xs font-medium bg-orange-500/20 text-orange-400 border border-orange-500/30">Mode: Rate Limit</span>
                @else
                    <span class="rounded-full px-3 py-1 text-xs font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">Mode: Log Only</span>
                @endif
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-6 py-8 space-y-8">

        <!-- Stats Row -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <p class="text-sm text-slate-400">Total Threats</p>
                <p class="text-2xl font-bold text-blue-400">{{ $stats['total'] }}</p>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <p class="text-sm text-slate-400">AI Crawlers</p>
                <p class="text-2xl font-bold text-purple-400">{{ $stats['ai_crawlers'] }}</p>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <p class="text-sm text-slate-400">Prompt Injections</p>
                <p class="text-2xl font-bold text-red-400">{{ $stats['prompt_injections'] }}</p>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <p class="text-sm text-slate-400">Data Harvesters</p>
                <p class="text-2xl font-bold text-orange-400">{{ $stats['data_harvesters'] }}</p>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <p class="text-sm text-slate-400">Blocked</p>
                <p class="text-2xl font-bold text-red-400">{{ $stats['blocked'] }}</p>
            </div>
            <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <p class="text-sm text-slate-400">Rate Limited</p>
                <p class="text-2xl font-bold text-yellow-400">{{ $stats['rate_limited'] }}</p>
            </div>
        </div>

        <!-- Two Column Row -->
        <div class="grid lg:grid-cols-2 gap-6">
            <!-- Top Sources -->
            <div class="bg-slate-800 rounded-lg border border-slate-700">
                <div class="px-5 py-4 border-b border-slate-700">
                    <h2 class="text-lg font-semibold text-white">Top Threat Sources</h2>
                </div>
                <div class="max-h-80 overflow-y-auto">
                    <table class="w-full text-sm">
                        <thead class="text-slate-400 text-left">
                            <tr class="border-b border-slate-700">
                                <th class="px-5 py-3">Source</th>
                                <th class="px-5 py-3 text-right">Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            @forelse($topSources as $source)
                                <tr class="border-b border-slate-700/50 hover:bg-slate-700">
                                    <td class="px-5 py-3">{{ $source->threat_source ?? 'Unknown' }}</td>
                                    <td class="px-5 py-3 text-right font-mono">{{ $source->total }}</td>
                                </tr>
                            @empty
                                <tr>
                                    <td colspan="2" class="px-5 py-6 text-center text-slate-500">No threats detected</td>
                                </tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Top IPs -->
            <div class="bg-slate-800 rounded-lg border border-slate-700">
                <div class="px-5 py-4 border-b border-slate-700">
                    <h2 class="text-lg font-semibold text-white">Top IPs</h2>
                </div>
                <div class="max-h-80 overflow-y-auto">
                    <table class="w-full text-sm">
                        <thead class="text-slate-400 text-left">
                            <tr class="border-b border-slate-700">
                                <th class="px-5 py-3">IP Address</th>
                                <th class="px-5 py-3 text-right">Hits</th>
                                <th class="px-5 py-3 text-right">Max Confidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            @forelse($topIps as $ip)
                                <tr class="border-b border-slate-700/50 hover:bg-slate-700">
                                    <td class="px-5 py-3 font-mono">{{ $ip->ip_address }}</td>
                                    <td class="px-5 py-3 text-right font-mono">{{ $ip->total }}</td>
                                    <td class="px-5 py-3 text-right font-mono">{{ $ip->confidence_score }}</td>
                                </tr>
                            @empty
                                <tr>
                                    <td colspan="3" class="px-5 py-6 text-center text-slate-500">No threats detected</td>
                                </tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Recent Threats -->
        <div class="bg-slate-800 rounded-lg border border-slate-700">
            <div class="px-5 py-4 border-b border-slate-700">
                <h2 class="text-lg font-semibold text-white">Recent Threats</h2>
            </div>
            <div class="max-h-96 overflow-y-auto">
                <table class="w-full text-sm">
                    <thead class="text-slate-400 text-left sticky top-0 bg-slate-800">
                        <tr class="border-b border-slate-700">
                            <th class="px-5 py-3">Time</th>
                            <th class="px-5 py-3">IP</th>
                            <th class="px-5 py-3">Type</th>
                            <th class="px-5 py-3">Source</th>
                            <th class="px-5 py-3">Confidence</th>
                            <th class="px-5 py-3">Action</th>
                            <th class="px-5 py-3">Pattern</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($recentThreats as $threat)
                            <tr class="border-b border-slate-700/50 hover:bg-slate-700">
                                <td class="px-5 py-3 text-slate-400 whitespace-nowrap">{{ $threat->created_at->format('H:i:s') }}</td>
                                <td class="px-5 py-3 font-mono">{{ $threat->ip_address }}</td>
                                <td class="px-5 py-3">
                                    @if($threat->threat_type === 'ai_crawler')
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-purple-500/20 text-purple-400">{{ $threat->getThreatTypeLabel() }}</span>
                                    @elseif($threat->threat_type === 'prompt_injection')
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-red-500/20 text-red-400">{{ $threat->getThreatTypeLabel() }}</span>
                                    @elseif($threat->threat_type === 'data_harvester')
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-orange-500/20 text-orange-400">{{ $threat->getThreatTypeLabel() }}</span>
                                    @else
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-slate-500/20 text-slate-400">{{ $threat->getThreatTypeLabel() }}</span>
                                    @endif
                                </td>
                                <td class="px-5 py-3">{{ $threat->threat_source ?? '—' }}</td>
                                <td class="px-5 py-3">
                                    @if($threat->confidence_score >= 90)
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-red-500/20 text-red-400">{{ $threat->confidence_score }}</span>
                                    @elseif($threat->confidence_score >= 70)
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-yellow-500/20 text-yellow-400">{{ $threat->confidence_score }}</span>
                                    @else
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-green-500/20 text-green-400">{{ $threat->confidence_score }}</span>
                                    @endif
                                </td>
                                <td class="px-5 py-3">
                                    @if($threat->action_taken === 'blocked')
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-red-500/20 text-red-400">{{ $threat->getActionLabel() }}</span>
                                    @elseif($threat->action_taken === 'rate_limited')
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-yellow-500/20 text-yellow-400">{{ $threat->getActionLabel() }}</span>
                                    @else
                                        <span class="rounded-full px-2 py-1 text-xs font-medium bg-slate-500/20 text-slate-400">{{ $threat->getActionLabel() }}</span>
                                    @endif
                                </td>
                                <td class="px-5 py-3 text-slate-400 truncate max-w-xs">{{ $threat->matched_pattern ?? '—' }}</td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="7" class="px-5 py-8 text-center text-slate-500">No threats in the last 24 hours</td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Bottom Info Bar -->
        <div class="flex flex-col sm:flex-row items-center justify-between text-sm text-slate-500 border-t border-slate-700 pt-4">
            <p>Monitoring {{ $detectorInfo['crawler_patterns_count'] }} crawler patterns &middot; {{ $detectorInfo['prompt_patterns'] }} injection patterns</p>
            <p>Last updated: {{ now()->format('H:i:s') }}</p>
        </div>

    </div>

</body>
</html>
