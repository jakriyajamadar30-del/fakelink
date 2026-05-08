from flask import Flask, request

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from urllib.parse import urlparse

import pandas as pd
import re

app = Flask(__name__)

# ---------------- DATASET ----------------

data = {

"url":[

# SAFE
"https://google.com",
"https://gmail.com",
"https://youtube.com",
"https://github.com",
"https://amazon.in",
"https://wikipedia.org",
"https://linkedin.com",
"https://microsoft.com",
"https://apple.com",
"https://openai.com",
"https://paypal.com",
"https://instagram.com",
"https://facebook.com",
"https://twitter.com",
"https://reddit.com",
"https://flipkart.com",
"https://spotify.com",
"https://whatsapp.com",
"https://telegram.org",
"https://zoom.us",
"https://python.org",
"https://bbc.com",
"https://mahanmk.com",

# FAKE
"https://mircosoft.com",
"https://micros0ft.com",
"https://rnicrosoft.com",
"https://g00gle.com",
"https://faceb00k.com",
"https://paypa1.com",

# PHISHING
"https://google-login-warning.com",
"https://google-account-security.xyz",
"https://gmail-password-reset-alert.net",
"https://youtube-premium-free.xyz",
"https://github-security-check.net",
"https://amazon-prize-claim.com",
"https://amazon-login-security.net",
"https://linkedin-account-warning.net",
"https://microsoft-security-account.com",
"https://paypal-secure-login.com",
"https://instagram-followers-free.xyz",
"https://facebook-security-alert.net",
"https://bank-login-warning.net",
"https://verify-account-security.net",
"https://claim-prize-now.xyz",
"https://secure-login-bank.com",
"https://google-free-reward.xyz",
"https://paypal-account-update.com",
"https://spotify-free-premium.xyz",
"https://telegram-security-alert.net",
"https://free-mobile-recharge.xyz",
"https://crypto-free-gift.net",
"https://google.verify-login-alert.com",
"https://paypal.verify-account-security.com",
"https://google---security---warning.xyz",
"https://amazon--secure-login.net",
"https://github_account_verify.xyz",
"https://login-free-reward-security.net",
"https://paypal@security-alert.com"

],

"label":[

# SAFE
0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,
0,0,0,

# FAKE
1,1,1,1,1,1,

# PHISHING
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,1,1,
1,1,1,1,1,1,1,1,1,1
]

}

df = pd.DataFrame(data)

# ---------------- MACHINE LEARNING ----------------

vectorizer = TfidfVectorizer(
    analyzer="char_wb",
    ngram_range=(3,6)
)

X = vectorizer.fit_transform(df["url"])

model = LogisticRegression(max_iter=5000)

model.fit(X, df["label"])

# ---------------- TRUSTED DOMAINS ----------------

trusted_domains = [

"google.com",
"youtube.com",
"github.com",
"amazon.in",
"microsoft.com",
"apple.com",
"paypal.com",
"facebook.com",
"instagram.com",
"openai.com",
"python.org",
"mahanmk.com",
"microsoftonline.com",
"login.microsoftonline.com",
"goo.gl",
"goo.gle"

]

# ---------------- SUSPICIOUS WORDS ----------------

suspicious_words = [

"login",
"verify",
"security",
"claim",
"free",
"warning",
"reward",
"alert",
"gift",
"premium",
"billing",
"reset",
"password",
"otp",
"bonus",
"win",
"prize",
"account",
"secure"

]

# ---------------- DANGEROUS DOMAINS ----------------

dangerous_domains = [

".xyz",
".tk",
".top",
".gq",
".test"

]

# ---------------- URL SHORTENERS ----------------

shorteners = [

"bit.ly",
"tinyurl.com",
"goo.gl",
"t.co"

]

# ---------------- PHISHING SCORE ----------------

def phishing_score(url):

    score = 0

    url_lower = url.lower()

    parsed = urlparse(url_lower)

    domain = parsed.netloc.replace("www.","")

    path = parsed.path.lower()

    # TRUSTED GOOGLE MAPS
    if domain in ["goo.gl","goo.gle"]:

        if "/maps/" in url_lower:
            return 0

    # TRUSTED DOMAINS
    if domain in trusted_domains:
        return 0

    for trusted in trusted_domains:

        if domain.endswith("." + trusted):
            return 0

    # SUSPICIOUS WORDS
    for word in suspicious_words:

        if word in domain:

            if word in ["login","verify","password","otp"]:
                score += 4

            else:
                score += 2

    # SUSPICIOUS PATH
    for word in suspicious_words:

        if word in path:
            score += 1

    # HYPHENS
    hyphen_count = domain.count("-")

    if hyphen_count == 1:
        score += 1

    elif hyphen_count == 2:
        score += 3

    elif hyphen_count >= 3:
        score += 5

    # DOUBLE HYPHENS
    if "--" in domain:
        score += 6

    # TRIPLE HYPHENS
    if "---" in domain:
        score += 8

    # MANY DOTS
    dot_count = domain.count(".")

    if dot_count >= 3:
        score += 4

    # UNDERSCORE
    if "_" in domain:
        score += 5

    # @ SYMBOL
    if "@" in url_lower:
        score += 10

    # DANGEROUS DOMAINS
    for d in dangerous_domains:

        if domain.endswith(d):
            score += 7

    # SHORTENERS
    for short in shorteners:

        if short in domain:
            score += 2

    # DANGEROUS FILES
    dangerous_files = [

        ".exe",
        ".apk",
        ".bat",
        ".zip"

    ]

    for file in dangerous_files:

        if file in path:
            score += 7

    # IP ADDRESS
    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 10

    # FAKE TRUSTED BRANDS
    for trusted in trusted_domains:

        brand = trusted.split(".")[0]

        if brand in domain:

            if domain != trusted and not domain.endswith("." + trusted):
                score += 8

        if brand.replace("o","0") in domain:
            score += 8

        if brand.replace("m","rn") in domain:
            score += 8

        if brand.replace("l","1") in domain:
            score += 8

    return score

# ---------------- HTML PAGE ----------------

HTML = """

<!DOCTYPE html>

<html>

<head>

<title>Link Detector</title>

<style>

body{

margin:0;
padding:0;
height:100vh;

display:flex;
justify-content:center;
align-items:center;

font-family:Arial;

background:linear-gradient(
135deg,
#0f2027,
#203a43,
#2c5364
);

}

.container{

background:white;

padding:35px;

width:500px;

border-radius:18px;

text-align:center;

box-shadow:0 12px 30px rgba(0,0,0,0.3);

}

h1{

font-size:34px;
margin-bottom:25px;

}

input{

width:100%;

padding:14px;

font-size:18px;

border-radius:10px;

border:1px solid #ccc;

margin-bottom:18px;

box-sizing:border-box;

}

button{

width:100%;

padding:14px;

font-size:20px;

border:none;

border-radius:10px;

cursor:pointer;

background:linear-gradient(
90deg,
#0072ff,
#0052d4
);

color:white;

}

.safe{

color:green;

font-size:24px;

font-weight:bold;

}

.danger{

color:red;

font-size:24px;

font-weight:bold;

}

.invalid{

color:red;

font-size:24px;

font-weight:bold;

}

.message{

font-size:18px;

font-weight:bold;

margin-top:10px;

}

</style>

</head>

<body>

<div class="container">

<h1>🛡️ LINK DETECTOR</h1>

<form method="POST">

<input
type="text"
name="url"
placeholder="Enter website link here..."
required
>

<button type="submit">

SCAN LINK

</button>

</form>

RESULT_BOX

</div>

</body>

</html>

"""

# ---------------- FLASK ----------------

@app.route("/", methods=["GET","POST"])

def home():

    result_html = ""

    if request.method == "POST":

        original_url = request.form["url"].strip()

        url = original_url

        # AUTO HTTPS
        if not url.startswith("http://") and not url.startswith("https://"):

            url = "https://" + url

        # VALIDATION
        domain_check = re.match(
            r"^https?://[A-Za-z0-9._@%/\-=]+\.[A-Za-z]{2,}",
            url
        )

        if not domain_check:

            result = "⚠️ Link is INVALID"

            message = "Enter valid website link"

            css = "invalid"

        else:

            parsed = urlparse(url)

            domain = parsed.netloc.replace("www.","")

            # ML PREDICTION
            X_test = vectorizer.transform([url])

            probability = model.predict_proba(X_test)[0][1]

            # PHISHING SCORE
            risk_score = phishing_score(url)

            # SAFE EXTENSIONS
            safe_extensions = [

                ".gov.in",
                ".edu",
                ".org",
                ".ac.in"

            ]

            for ext in safe_extensions:

                if domain.endswith(ext):
                    risk_score -= 2

            if risk_score < 0:
                risk_score = 0

            # TRUSTED SUBDOMAIN
            trusted_subdomain = False

            for trusted in trusted_domains:

                if domain == trusted or domain.endswith("." + trusted):

                    trusted_subdomain = True

                    break

            # DANGEROUS PATTERN
            dangerous_pattern = (

                "@" in url
                or ".xyz" in domain
                or "--" in domain
                or "login" in domain
                or "verify" in domain
                or "password" in domain
                or "otp" in domain

            )

            # FINAL DETECTION
            if (

                probability >= 0.90

                or

                (probability >= 0.70 and risk_score >= 5)

                or

                risk_score >= 8

                or

                (dangerous_pattern and risk_score >= 5)

            ):

                result = "⚠️ Warning - Link is PHISHING"

                message = "❌ Do NOT click this link"

                css = "danger"

            elif (

                trusted_subdomain

                or

                (
                    probability < 0.50
                    and risk_score <= 3
                )

            ):

                result = "👍 Link is SAFE"

                message = "Secure to browse or click"

                css = "safe"

            else:

                result = "⚠️ Warning - Link is PHISHING"

                message = "❌ Do NOT click this link"

                css = "danger"

        result_html = f'''

        <div class="{css}">
        {result}
        </div>

        <div class="message">
        {message}
        </div>

        '''

    return HTML.replace("RESULT_BOX", result_html)

# ---------------- RUN ----------------

if __name__ == "__main__":

    app.run(debug=True)