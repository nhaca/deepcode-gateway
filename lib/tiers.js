/**
 * tiers.js — SINGLE SOURCE OF TRUTH cho tier system
 *
 * Dung cho: IDE (main.js, ai-panel.js), Gateway (security.js, api-keys.js, chat.js)
 * Khong duoc define tier config o noi khac — chi import file nay.
 */

const TIERS = ['free', 'pro', 'premium', 'business'];

const TIER_ORDER = { free: 0, pro: 1, premium: 2, business: 3 };

// Tokens per month
const CREDITS = {
    free: 100_000,
    pro: 1_000_000,
    premium: 5_000_000,
    business: 100_000_000,
};

// Max context window (tokens)
const CONTEXT = {
    free: 32_768,
    pro: 65_536,
    premium: 131_072,
    business: 262_144,
};

// Requests per minute
const RATE_LIMITS = {
    free: 20,
    pro: 40,
    premium: 60,
    business: 120,
};

// Context resets per 2 weeks
const RESET_LIMITS = {
    free: 2,
    pro: 5,
    premium: 10,
    business: 20,
};

// Gateway version access (v1=free, v2=pro, v3=premium, v4=business)
const VERSION_ACCESS = {
    free: 1,
    pro: 2,
    premium: 3,
    business: 4,
};

// Display names
const TIER_NAMES = {
    free: 'Free',
    pro: 'PRO',
    premium: 'Premium',
    business: 'Business',
};

// Rank helper
function tierRank(tier) {
    return TIER_ORDER[tier] ?? 0;
}

function canAccessTier(userTier, requiredTier) {
    return tierRank(userTier) >= tierRank(requiredTier);
}

function canAccessVersion(userTier, version) {
    return (VERSION_ACCESS[userTier] ?? 0) >= version;
}

module.exports = {
    TIERS,
    TIER_ORDER,
    CREDITS,
    CONTEXT,
    RATE_LIMITS,
    RESET_LIMITS,
    VERSION_ACCESS,
    TIER_NAMES,
    tierRank,
    canAccessTier,
    canAccessVersion,
};
