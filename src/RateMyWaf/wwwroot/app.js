// Small browser helpers for RateMyWAF (theme, storage, downloads, clipboard).
window.rmw = {
    toggleTheme: function () {
        var root = document.documentElement;
        var current = root.getAttribute('data-theme');
        if (!current) {
            current = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }
        var next = current === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-theme', next);
        try { localStorage.setItem('rmw-theme', next); } catch (e) { }
    },

    getItem: function (key) {
        try { return sessionStorage.getItem(key); } catch (e) { return null; }
    },

    setItem: function (key, value) {
        try {
            if (value === null || value === undefined) sessionStorage.removeItem(key);
            else sessionStorage.setItem(key, value);
        } catch (e) { }
    },

    download: function (fileName, base64, mimeType) {
        var bytes = atob(base64);
        var arr = new Uint8Array(bytes.length);
        for (var i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
        var blob = new Blob([arr], { type: mimeType });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    },

    copy: async function (text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (e) {
            try {
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                var ok = document.execCommand('copy');
                document.body.removeChild(ta);
                return ok;
            } catch (e2) { return false; }
        }
    }
};
