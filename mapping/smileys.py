"""
Smiley Translation

Maps between Yahoo Messenger smiley codes and Discord emoji.

Yahoo format: :) :( ;) :D etc or :(|) for custom codes
Discord format: Unicode emoji or :emoji_name:
"""

# Yahoo Messenger smiley codes -> Discord emoji
YAHOO_TO_DISCORD = {
    # Basic smileys
    ':)': '🙂',
    ':-)': '🙂',
    ':(': '😞',
    ':-(': '😞',
    ';)': '😉',
    ';-)': '😉',
    ':D': '😃',
    ':-D': '😃',
    ':P': '😛',
    ':-P': '😛',
    ':p': '😛',
    ':-p': '😛',
    ':O': '😮',
    ':-O': '😮',
    ':o': '😮',
    ':-o': '😮',
    ':|': '😐',
    ':-|': '😐',
    ':*': '😘',
    ':-*': '😘',
    '>:)': '😈',
    '>:-)': '😈',
    ":'(": '😢',
    ":'-(": '😢',
    ':$': '😳',
    ':-$': '😳',
    'B)': '😎',
    'B-)': '😎',
    '8)': '😎',
    '8-)': '😎',
    ':^)': '🤥',
    'O:)': '😇',
    'O:-)': '😇',
    '</3': '💔',
    '<3': '❤️',

    # Yahoo specific codes
    ':-??': '🤔',
    ':-S': '😖',
    ':-s': '😖',
    '>:D<': '🤗',
    ':-h': '🤞',
    ':-t': '😤',
    '[-O<': '🙏',
    '@};-': '🌹',
    '**==': '🏁',
    '(%)': '☯️',
    ':-L': '😓',
    ':)>-': '✌️',
    '[-X': '🤐',
    '\\:D/': '🎉',
    '>:/': '😠',
    ';))': '😏',
    ':-<': '😢',
    '#:-S': '😵',
    '=P~': '🤤',
    ':-"': '😬',
    '8-|': '🤓',
    ':^o': '🤥',
    ':-w': '😶',
    ':-<': '😞',
    ':)': '🙂',

    # Actions (Yahoo has animated versions)
    '=D>': '👏',
    ':-@': '😡',
    '(*)': '⭐',
    '(%-)': '😵‍💫',
    '[..]': '🎧',
}

# Discord emoji -> Yahoo Messenger codes (reverse mapping)
DISCORD_TO_YAHOO = {v: k for k, v in YAHOO_TO_DISCORD.items()}

# Additional Discord to Yahoo mappings (where multiple Yahoo codes map to same emoji)
DISCORD_TO_YAHOO.update({
    '😀': ':D',
    '😁': ':D',
    '😂': ':D',
    '🤣': ':D',
    '😊': ':)',
    '😋': ':P',
    '😜': ';P',
    '😝': ':P',
    '🙁': ':(',
    '😕': ':/',
    '😫': ":'(",
    '😭': ":'(",
    '😤': ':-t',
    '😠': '>:/',
    '😡': ':-@',
    '🥰': ':*',
    '😍': ':*',
    '🤩': ':D',
    '🤔': ':-??',
    '🤫': ':-$',
    '🤭': ':$',
    '🙄': '8-|',
    '👍': ':)>-',
    '👎': ':(',
    '❤️': '<3',
    '💕': '<3',
    '💖': '<3',
    '💗': '<3',
    '💘': '<3',
    '💝': '<3',
})


def yahoo_to_discord(text: str) -> str:
    """Convert Yahoo smiley codes in text to Discord emoji"""
    result = text

    # Sort by length (longest first) to avoid partial replacements
    sorted_codes = sorted(YAHOO_TO_DISCORD.keys(), key=len, reverse=True)

    for yahoo_code in sorted_codes:
        discord_emoji = YAHOO_TO_DISCORD[yahoo_code]
        result = result.replace(yahoo_code, discord_emoji)

    return result


def discord_to_yahoo(text: str) -> str:
    """Convert Discord emoji in text to Yahoo smiley codes"""
    result = text

    for discord_emoji, yahoo_code in DISCORD_TO_YAHOO.items():
        result = result.replace(discord_emoji, yahoo_code)

    return result


def strip_yahoo_formatting(text: str) -> str:
    """
    Strip Yahoo Messenger HTML-like formatting tags.

    Yahoo uses tags like:
    - <font face="...">
    - <FADE #color1,#color2>
    - [1m (bold), [0m (reset)
    """
    import re

    # Remove font tags
    text = re.sub(r'<font[^>]*>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'</font>', '', text, flags=re.IGNORECASE)

    # Remove FADE tags
    text = re.sub(r'<FADE[^>]*>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'</FADE>', '', text, flags=re.IGNORECASE)

    # Remove ANSI-style codes
    text = re.sub(r'\[\d+m', '', text)

    # Remove other common formatting
    text = re.sub(r'<[biu]>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'</[biu]>', '', text, flags=re.IGNORECASE)

    return text.strip()
