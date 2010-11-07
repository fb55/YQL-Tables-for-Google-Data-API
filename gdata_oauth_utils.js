function buildRequest(queryBodyParams, headParams, method, reqURL, consumer_secret, token_secret) {

    //nonce-function by Netflix (for JS OAuth library)
    function nonce(ans) {
        var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
        var result = "";
        for (var i = 0; i < ans; ++i) {
            var rnum = Math.floor(Math.random() * chars.length);
            result += chars.substring(rnum, rnum + 1);
        }
        return result;
    }

    var timestamp = Math.round((new Date()).getTime() / 1000);

    headParams.push(
            ["oauth_signature_method", "HMAC-SHA1"],
            ["oauth_version", "1.0"],
            ["oauth_timestamp", timestamp],
            ["oauth_nonce", nonce(20)]);

    var allParams = method + "&" + encodeURIComponent(reqURL) + "&" + (function() {
        //join both param-strings, sort them
        var pars = [];
        pars.push.apply(pars, queryBodyParams);
        pars.push.apply(pars, headParams);
        pars.sort(function(a, b) {
            if (a[0] !== b[0]) {
                return a[0] > b[0] ? 1 : (-1);
            }
            return a[1] > b[1] ? 1 : (-1);
        });

        var rets = [];
        var ans = pars.length;
        for (var i = 0; i < ans; i++) {
            if (pars[i].length < 2) {
                continue;
            }
            rets.push(pars[i][0] + "=" + encodeURIComponent(pars[i][1]));
        }
        return encodeURIComponent( rets.join("&") );
    })();

    //build signature
    headParams.push(["oauth_signature", y.crypto.encodeHmacSHA1(
    encodeURIComponent(consumer_secret) + "&" + encodeURIComponent(token_secret), allParams)]);

    var authHeader = "OAuth " + (function() {
        var pars = [];
        var ans = headParams.length;
        for (var i = 0; i < ans; i++) {
            pars[i] = headParams[i][0] + "=\"" + encodeURIComponent(headParams[i][1]) + "\"";
        }
        return pars.join(", ");
    })();

    var req = y.rest(reqURL).header("Authorization", authHeader);

    for (var i = 0; i < queryBodyParams.length; i++) {
        req.query(queryBodyParams[i][0], queryBodyParams[i][1]);
    }

    return req;
}