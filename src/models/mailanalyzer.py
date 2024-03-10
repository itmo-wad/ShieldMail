import re
import language_tool_python
import textstat
import requests

class EmailAnalyzer:
    def __init__(self, perspective_api_key):
        self.tool = language_tool_python.LanguageTool('auto')
        self.api_key = perspective_api_key

    def included_urls(self,text):
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        urls = re.findall(url_pattern, text)
        return urls

    def detect_phishing(self,text):
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        api_url = f"{endpoint}?key={self.api_key}"

        for url in self.included_urls(text):
            request_body = {
                "client": {
                    "clientId": "wad-itmo-shieldmail",
                    "clientVersion": "1.0",
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }

            response = requests.post(api_url, json=request_body)
            response_data = response.json()

            if "matches" in response_data:
                return True

        return False

    def detect_spam(self,text):
        endpoint = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

        params = {"key": self.api_key}
        data = {
            "comment": {"text": text},
            "languages": ["en"],
            "requestedAttributes": {
                "SPAM": {},
            },
        }

        response = requests.post(endpoint, params=params, json=data)
        results = response.json()

        spam_score = results["attributeScores"]["SPAM"]["summaryScore"]["value"]
        return True if (spam_score > 0.7) else False

    def lexical_diversity(self, text):
        nosign_text = re.sub(r'[^\w\s]', '', text)
        words = nosign_text.lower().split()
        unique_words = set(words)
        lexical_diversity = len(unique_words) / len(words)
        return lexical_diversity

    def grammar_checker(self, text):
        grammar_issues = self.tool.check(text)
        return len(grammar_issues)

    def flesch_reading_ease(self, text):
        sentences = re.split(r'[.!?]', text)
        sentence_lengths = [len(re.findall(r'\b\w+\b', sentence)) for sentence in sentences if sentence.strip()]
        avg_sentence_length = sum(sentence_lengths) / len(sentence_lengths) if len(sentence_lengths) > 0 else 0

        words = re.findall(r'\b\w+\b', text)
        total_syllables = sum(textstat.syllable_count(word) for word in words)
        avg_syllables_per_word = total_syllables / len(words) if len(words) > 0 else 0

        flesch_score = 206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables_per_word)
        return min(flesch_score, 100)

    def analyze_text_with_perspective(self, text):
        endpoint = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

        params = {"key": self.api_key}
        data = {
            "comment": {"text": text},
            "languages": ["en"],
            "requestedAttributes": {
                "TOXICITY": {},
                "SPAM": {},
                "INSULT": {},
                "INCOHERENT": {},
            },
        }

        response = requests.post(endpoint, params=params, json=data)
        results = response.json()

        toxicity_score = results["attributeScores"]["TOXICITY"]["summaryScore"]["value"]
        spam_score = results["attributeScores"]["SPAM"]["summaryScore"]["value"]
        incoherent_score = results["attributeScores"]["INCOHERENT"]["summaryScore"]["value"]

        return toxicity_score, spam_score, incoherent_score

    def calculate_risk_score(self, text):

        toxicity_score, spam_score, incoherent_score = self.analyze_text_with_perspective(text)

        if self.detect_phishing(text):
            return 100
        elif self.detect_spam(text):
            return round(100*spam_score)

        else:
            lexical_diversity_weight = 0.1
            flesch_reading_ease_weight = 0.1
            links_weight = 0.3 if len(self.included_urls(text)) else 0
            toxicity_score_weight = 0.1
            spam_score_weight = 0.3
            incoherent_score_weight = 0.1

            lexical_diversity_score = self.lexical_diversity(text)
            flesch_reading_ease_score = self.flesch_reading_ease(text)/100

            risk_score = (
                    lexical_diversity_score * lexical_diversity_weight +
                    flesch_reading_ease_score * flesch_reading_ease_weight +
                    links_weight +
                    toxicity_score * toxicity_score_weight +
                    spam_score * spam_score_weight +
                    incoherent_score * incoherent_score_weight
            )

            return round(risk_score*100)





