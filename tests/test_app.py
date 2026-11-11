import unittest

from app import analyze_email, app


class AnalyzeEmailTests(unittest.TestCase):
    def test_normal_message_has_no_detected_warning_signs(self):
        result = analyze_email(
            "Meeting notes",
            "alex@example.com",
            "Here are the notes from our meeting. See you tomorrow.",
        )

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk"], "Low")
        self.assertEqual(result["findings"], [])

    def test_suspicious_phrases_and_links_raise_score(self):
        result = analyze_email(
            "Urgent action required",
            "IT Support",
            "Verify your account within 24 hours at http://192.0.2.10/login",
        )

        self.assertEqual(result["risk"], "High")
        self.assertGreaterEqual(result["score"], 50)
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Urgent or threatening language", titles)
        self.assertIn("Request for sensitive information", titles)
        self.assertIn("Link uses an IP address", titles)
        self.assertIn("Link does not use HTTPS", titles)

    def test_shortened_https_link_is_reported(self):
        result = analyze_email("", "", "Read more: https://bit.ly/example")

        self.assertEqual(result["risk"], "Low")
        self.assertEqual(result["score"], 20)
        self.assertEqual(result["findings"][0]["title"], "Link uses a URL shortener")

    def test_malformed_url_is_reported_without_crashing(self):
        result = analyze_email("", "", "Visit http://[ for details.")

        self.assertEqual(result["score"], 10)
        self.assertEqual(result["findings"][0]["title"], "Malformed link format")


class FlaskAppTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_home_page_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Phishing email checker", response.data)

    def test_post_displays_analysis(self):
        response = self.client.post(
            "/",
            data={"subject": "Hello", "sender": "", "body": "See you soon."},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No warning signs", response.data)

    def test_empty_message_is_rejected(self):
        response = self.client.post("/", data={"body": "  "})

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Paste the email message", response.data)

    def test_long_message_is_rejected(self):
        response = self.client.post("/", data={"body": "x" * 20_001})

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"longer than the allowed limit", response.data)


if __name__ == "__main__":
    unittest.main()
