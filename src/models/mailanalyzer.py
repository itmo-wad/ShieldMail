import re
import language_tool_python
import textstat
import requests
import bleach

class EmailAnalyzer:
    def __init__(self, perspective_api_key,rapid_api_key,text):
        self.tool = language_tool_python.LanguageTool('auto')
        self.api_key = perspective_api_key
        self.api_key2 = rapid_api_key
        self.message = bleach.clean(text)

    def included_urls(self):
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        urls = re.findall(url_pattern, self.message)
        return urls

    def detect_phishing(self):
        host = "https://exerra-phishing-check.p.rapidapi.com/"

        for url in self.included_urls():
            payload = {"url": url}
            headers = {
            "X-RapidAPI-Key": self.api_key2,
            "X-RapidAPI-Host": "exerra-phishing-check.p.rapidapi.com"
            }
            response = requests.get(host, headers=headers, params=payload)
            detected = response.json()['data']['isScam']
            if detected:
                return detected
        return detected

    def detect_spam(self):
        endpoint = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

        params = {"key": self.api_key}
        data = {
            "comment": {"text": self.message},
            "languages": ["en"],
            "requestedAttributes": {
                "SPAM": {},
            },
        }

        response = requests.post(endpoint, params=params, json=data)
        results = response.json()

        spam_score = results["attributeScores"]["SPAM"]["summaryScore"]["value"]
        return True if (spam_score > 0.7) else False

    def lexical_diversity(self):
        nosign_text = re.sub(r'[^\w\s]', '', self.message)
        words = nosign_text.lower().split()
        unique_words = set(words)
        lexical_diversity = len(unique_words) / len(words)
        return round(lexical_diversity,2)

    def grammar_checker(self):
        grammar_issues = self.tool.check(self.message)
        return len(grammar_issues)

    def flesch_reading_ease(self, text):
        sentences = re.split(r'[.!?]', text)
        sentence_lengths = [len(re.findall(r'\b\w+\b', sentence)) for sentence in sentences if sentence.strip()]
        avg_sentence_length = sum(sentence_lengths) / len(sentence_lengths) if len(sentence_lengths) > 0 else 0

        words = re.findall(r'\b\w+\b', text)
        total_syllables = sum(textstat.syllable_count(word) for word in words)
        avg_syllables_per_word = total_syllables / len(words) if len(words) > 0 else 0

        flesch_score = 206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables_per_word)
        flesch_score = round(min(flesch_score, 100), 2)

    def toxicity_score(self):
        endpoint = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

        params = {"key": self.api_key}
        data = {
            "comment": {"text": self.message},
            "languages": ["en"],
            "requestedAttributes": {
                "TOXICITY": {},
            },
        }

        response = requests.post(endpoint, params=params, json=data)
        results = response.json()

        toxicity_score = results["attributeScores"]["TOXICITY"]["summaryScore"]["value"]

        return round(toxicity_score,2)

    def spam_score(self):
        endpoint = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

        params = {"key": self.api_key}
        data = {
            "comment": {"text": self.message},
            "languages": ["en"],
            "requestedAttributes": {
                "SPAM": {},
            },
        }

        response = requests.post(endpoint, params=params, json=data)
        results = response.json()

        spam_score = results["attributeScores"]["SPAM"]["summaryScore"]["value"]

        return round(spam_score,2)

    def incoherence_score(self):
        endpoint = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

        params = {"key": self.api_key}
        data = {
            "comment": {"text": self.message},
            "languages": ["en"],
            "requestedAttributes": {
                "INCOHERENT": {},
            },
        }

        response = requests.post(endpoint, params=params, json=data)
        results = response.json()

        incoherent_score = results["attributeScores"]["INCOHERENT"]["summaryScore"]["value"]

        return round(incoherent_score,2)

    def calculate_risk_score(self):

        if self.detect_phishing():
            return 100
        elif self.detect_spam():
            return round(100*self.spam_score())

        else:
            lexical_diversity_weight = 0.1
            flesch_reading_ease_weight = 0.1
            links_weight = 0.3 if len(self.included_urls()) else 0
            toxicity_score_weight = 0.1
            spam_score_weight = 0.3
            incoherent_score_weight = 0.1

            risk_score = (
                    self.lexical_diversity() * lexical_diversity_weight +
                    (self.flesch_reading_ease()/100) * flesch_reading_ease_weight +
                    links_weight +
                    self.toxicity_score() * toxicity_score_weight +
                    self.spam_score() * spam_score_weight +
                    self.incoherence_score() * incoherent_score_weight
            )

            return round(risk_score*100)

