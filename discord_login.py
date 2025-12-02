"""
Discord Login Helper

Opens a webview window for Discord login and extracts the token automatically.
This replicates the "Sign in with Discord" experience users are familiar with.
"""

import logging

logger = logging.getLogger(__name__)

# JavaScript to extract the Discord token from localStorage
EXTRACT_TOKEN_JS = """
(function() {
    var token = null;

    // Method 1: Direct localStorage
    try {
        var stored = localStorage.getItem('token');
        if (stored) {
            token = stored.replace(/"/g, '');
        }
    } catch(e) {}

    // Method 2: iframe trick
    if (!token) {
        try {
            var iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            document.body.appendChild(iframe);
            token = iframe.contentWindow.localStorage.getItem('token');
            if (token) token = token.replace(/"/g, '');
            iframe.remove();
        } catch(e) {}
    }

    // Method 3: Search all localStorage
    if (!token) {
        try {
            for (var i = 0; i < localStorage.length; i++) {
                var key = localStorage.key(i);
                var value = localStorage.getItem(key);
                if (value && typeof value === 'string' && value.length > 50 && value.includes('.')) {
                    var parts = value.replace(/"/g, '').split('.');
                    if (parts.length >= 2) {
                        token = value.replace(/"/g, '');
                        break;
                    }
                }
            }
        } catch(e) {}
    }

    return token;
})();
"""

CHECK_LOGGED_IN_JS = """
(function() {
    return window.location.pathname.startsWith('/channels') ||
           window.location.pathname.startsWith('/app') ||
           document.querySelector('[class*="privateChannels"]') !== null ||
           document.querySelector('[data-list-id="private-channels"]') !== null;
})();
"""


def open_discord_login():
    """
    Open Discord login window and return the token.

    This BLOCKS until the user logs in or closes the window.
    Must be called from the main thread.

    Returns:
        str: The Discord token, or None if cancelled/failed
    """
    try:
        import webview
    except ImportError:
        logger.error("pywebview not installed")
        return None

    result = {'token': None}
    window = None

    def check_for_token():
        """Check if logged in and extract token"""
        nonlocal window
        if not window:
            return

        try:
            is_logged_in = window.evaluate_js(CHECK_LOGGED_IN_JS)

            if is_logged_in:
                token = window.evaluate_js(EXTRACT_TOKEN_JS)
                if token and len(str(token)) > 50:
                    result['token'] = token
                    logger.info("Successfully extracted Discord token")
                    window.destroy()
                    return

            # Check again in 1 second
            import threading
            timer = threading.Timer(1.0, check_for_token)
            timer.daemon = True
            timer.start()

        except Exception as e:
            logger.error(f"Error checking for token: {e}")
            import threading
            timer = threading.Timer(2.0, check_for_token)
            timer.daemon = True
            timer.start()

    def on_loaded():
        check_for_token()

    # Create and show window
    window = webview.create_window(
        title='Sign in to Discord',
        url='https://discord.com/login',
        width=450,
        height=700,
        resizable=False
    )

    window.events.loaded += on_loaded

    # This blocks until window is closed
    # Use mshtml (IE) engine for Windows 7 compatibility
    try:
        webview.start(gui='mshtml')
    except Exception:
        # Fall back to default if mshtml fails
        webview.start()

    return result['token']


# Simple test
if __name__ == '__main__':
    print("Opening Discord login...")
    token = open_discord_login()
    if token:
        print(f"Got token: {token[:20]}...")
    else:
        print("Login cancelled")
