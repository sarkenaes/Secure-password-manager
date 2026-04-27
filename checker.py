"""Password strength checking logic.

This module checks a password using several real-world signals:
- length and character variety
- estimated entropy and crack time
- local dictionary/common-password check
- optional Have I Been Pwned k-anonymity breach check
"""

import hashlib
import math
from pathlib import Path
from typing import Dict, List, Optional

import requests

WORDS_FILE = Path(__file__).resolve().parent / "data" / "words.txt"
HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"
GUESSES_PER_SECOND = 1_000_000


def load_common_words(path: Path = WORDS_FILE) -> set[str]:
    """Load common passwords/words into a set for fast lookup."""
    words: set[str] = set()
    if not path.exists():
        return words

    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            word = line.strip().lower()
            if word:
                words.add(word)
    return words


_COMMON_WORDS = load_common_words()


def character_pool_size(password: str) -> int:
    """Estimate the possible character pool size used by a password."""
    pool = 0
    specials = "`~!@#$%^&*()_+=-[]|}{;:\"'>?<,./?"

    if any(ch.isdigit() for ch in password):
        pool += 10
    if any(ch.islower() for ch in password):
        pool += 26
    if any(ch.isupper() for ch in password):
        pool += 26
    if any(ch in specials for ch in password):
        pool += len(specials)

    return pool


def calculate_entropy(password: str) -> float:
    """Calculate password entropy using length * log2(character pool)."""
    if not password:
        return 0.0

    pool = character_pool_size(password)
    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def estimate_crack_time_seconds(password: str) -> float:
    """Estimate brute-force crack time in seconds."""
    entropy = calculate_entropy(password)
    total_guesses = 2 ** entropy
    return total_guesses / GUESSES_PER_SECOND


def format_crack_time(seconds: float) -> str:
    """Convert seconds into a user-friendly time estimate."""
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} hours"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.0f} days"
    return f"{seconds / 31_536_000:.0f} years"


def check_pwned_password(password: str) -> Optional[int]:
    """Check if a password appears in Have I Been Pwned's password database.

    Uses the k-anonymity API: only the first five SHA-1 hash characters are sent.
    Returns the breach count if found, 0 if not found, or None if the API fails.
    """
    if not password:
        return 0

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(
            HIBP_API_URL.format(prefix),
            headers={"User-Agent": "SecurePasswordToolkit"},
            timeout=8,
        )
        response.raise_for_status()
    except requests.RequestException:
        return None

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


def check_password_strength(password: str, check_breaches: bool = True) -> Dict[str, object]:
    """Return a full password analysis report."""
    score = 0
    tips: List[str] = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        tips.append("Use at least 8 characters; 12+ is better.")

    if any(ch.islower() for ch in password):
        score += 1
    else:
        tips.append("Add at least one lowercase letter.")

    if any(ch.isupper() for ch in password):
        score += 1
    else:
        tips.append("Add at least one uppercase letter.")

    if any(ch.isdigit() for ch in password):
        score += 1
    else:
        tips.append("Add at least one number.")

    if any(not ch.isalnum() for ch in password):
        score += 1
    else:
        tips.append("Add at least one special character.")

    is_dictionary_word = password.lower() in _COMMON_WORDS
    if is_dictionary_word:
        score = max(0, score - 2)
        tips.append("This password appears in the local common-password wordlist.")

    pwned_count = None
    if check_breaches:
        pwned_count = check_pwned_password(password)
        if pwned_count is None:
            tips.append("Breach check unavailable right now; try again later.")
        elif pwned_count > 0:
            score = 0
            tips.append(f"This password appears in {pwned_count:,} known breaches. Do not use it.")
        else:
            score += 1

    entropy = calculate_entropy(password)
    crack_seconds = estimate_crack_time_seconds(password)

    if score >= 6 and entropy >= 60:
        strength = "strong"
    elif score >= 4 and entropy >= 35:
        strength = "medium"
    else:
        strength = "weak"

    if not tips:
        tips.append("Good password structure. Avoid reusing it across websites.")

    return {
        "password_length": len(password),
        "score": score,
        "strength": strength,
        "entropy": round(entropy, 2),
        "crack_time": format_crack_time(crack_seconds),
        "pwned_count": pwned_count,
        "dictionary_match": is_dictionary_word,
        "tips": tips,
    }
