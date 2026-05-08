from flask import Flask, render_template_string, request
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from urllib.parse import urlparse
import re

app = Flask(__name__)

# ---------------- DATASET ----------------

data = {

    "url":[

"https://google.com",
"https://gmail.com",
"https://youtube.com",
"https://github.com",
"https://amazon.in",
"https://microsoft.com",
"https://openai.com",
"https://paypal.com",
"https://facebook.com",
"https://instagram.com",
"https://python.org",

"https://mircosoft.com",
"https://g00gle.com",
"https://paypa1.com",

"https://google-login-warning.com",
"https://google-account-security.xyz",
"https://paypal-secure-login.com",
"https://amazon-prize-claim.com",
"https://free-mobile-recharge.xyz",
"https://verify-account-security.net",

],

"label":[

0,0,0,0,0,0,0,0,0,0,0,

1,1,1,

1,1,1,1,1,1

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
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "openai.com",
    "python.org"
]

# ---------------- PHISHING SCORE ----------------

def phishing_score(url):

    score = 0

    parsed = urlparse(url.lower())

    domain = parsed.netloc.replace("www.", "")

    suspicious_words = [
        "login",
        "verify",
        "security",
        "free",
        "reward",
        "claim",
        "warning",
        "password",
        "otp"
    ]

    for word in suspicious_words:

        if word in domain:
            score += 3

    if ".xyz" in domain:
        score += 6

    if "--" in domain:
        score += 5

    if "@" in url:
        score += 8

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 10

    return score

# ---------------- HTML + CSS ----------------

HTML = """

<!DOCTYPE html>
<html>

<head>

<title>Link Detector</title>

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

*{
    margin:0;
    padding:0;
    box-sizing:border-box;
}

body{

    min-height:100vh;

    display:flex;
    justify-content:center;
    align-items:center;

    font-family:Arial, sans-serif;

    background:
    linear-gradient(
        135deg,
        #0f2027,
        #203a43,
        #2c5364
    );
}

.container{

    width:90%;
    max-width:520px;

    padding:35px;

    border-radius:25px;

    background:rgba(255,255,255,0.12);

    backdrop-filter:blur(18px);

    border:1px solid rgba(255,255,255,0.2);

    box-shadow:
    0 10px 40px rgba(0,0,0,0.35);

    text-align:center;
}

h1{

    color:white;

    margin-bottom:25px;

    font-size:34px;
}

input{

    width:100%;

    padding:15px;

    border:none;

    border-radius:14px;

    outline:none;

    font-size:17px;

    margin-bottom:20px;
}

button{

    width:100%;

    padding:15px;

    border:none;

    border-radius:14px;

    font-size:18px;

    font-weight:bold;

    color:white;

    cursor:pointer;

    background:
    linear-gradient(
        90deg,
        #00c6ff,
        #0072ff
    );
}

button:hover{

    opacity:0.9;
}

#resultBox{

    margin-top:28px;
}

.safe,
.danger,
.invalid{

    padding:18px;

    border-radius:16px;

    font-size:24px;

    font-weight:bold;

    color:white;

    margin-bottom:12px;
}

.safe{

    background:#16a34a;
}

.danger{

    background:#dc2626;
}

.invalid{

    background:#f59e0b;
}

.message{

    font-size:18px;

    font-weight:bold;

    color:white;

    margin-top:10px;
}

canvas{

    margin-top:25px !important;

    max-width:280px;

    margin-left:auto;
    margin-right:auto;
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
value="{{ url }}"
placeholder="Enter website link here..."
required
>

<button type="submit">
SCAN LINK
</button>

</form>

<div id="resultBox">

{% if result %}

<div class="
{% if 'SAFE' in result %}
safe
{% elif 'PHISHING' in result %}
danger
{% else %}
invalid
{% endif %}
">

{{ result }}

</div>

<div class="message">

{{ message }}

</div>

<canvas id="riskChart"></canvas>

{% endif %}

</div>

</div>

<script>

const score = {{ score|default(0) }};

if(score > 0){

    const ctx =
    document.getElementById('riskChart');

    new Chart(ctx, {

        type: 'pie',

        data: {

            labels: ['Risk', 'Safe'],

            datasets: [{

                data: [score, 20-score]

            }]
        }
    });
}

</script>

</body>
</html>

"""

# ---------------- FLASK ----------------

@app.route("/", methods=["GET", "POST"])

def home():

    result = ""
    message = ""
    url = ""
    risk_score = 0

    if request.method == "POST":

        url = request.form["url"].strip()

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        domain_check = re.match(
            r"^https?://[A-Za-z0-9._@%/\-=]+\.[A-Za-z]{2,}",
            url
        )

        if not domain_check:

            result = "⚠️ INVALID LINK"
            message = "Enter valid website URL"

        else:

            parsed = urlparse(url)

            domain = parsed.netloc.replace("www.", "")

            X_test = vectorizer.transform([url])

            probability = model.predict_proba(X_test)[0][1]

            risk_score = phishing_score(url)

            trusted = False

            for d in trusted_domains:

                if domain == d or domain.endswith("." + d):
                    trusted = True

            if probability >= 0.80 or risk_score >= 6:

                result = "⚠️ WARNING : PHISHING LINK"
                message = "❌ Do NOT open this link"

            elif trusted:

                result = "✅ LINK IS SAFE"
                message = "Secure website detected"

            else:

                result = "⚠️ SUSPICIOUS LINK"
                message = "Proceed carefully"

    return render_template_string(
        HTML,
        result=result,
        message=message,
        score=risk_score,
        url=url
    )

# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(debug=True)
