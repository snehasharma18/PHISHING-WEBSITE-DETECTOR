from urllib.parse import urlparse

class feature_extractor:
    def __init__(self, url):
        self.url = url
    
    def extract_features(self):
        features = {
            "long_url": self._classify_long_url(),
            "having_@_symbol": self._has_at_symbol(),
            "redirection_//_symbol": self._check_redirection_double_slash(),
            "prefix_suffix_seperation": self._has_prefix_suffix(),
            "sub_domains": self._classify_sub_domains(),
        }
        return features

    def _classify_long_url(self):
        """
        Classifies URLs based on their length:
        - <54 characters: Legitimate (0)
        - >=54 characters: Phishing (1)
        """
        url_length = len(self.url)
        if url_length < 54:
            return 0  # Legitimate
        elif 54 <= url_length <= 75:
            return 2  # Suspicious
        else:
            return 1  # Phishing

    def _has_at_symbol(self):
        """
        Checks if '@' symbol exists in the URL.
        - Yes: Phishing (1)
        - No: Legitimate (0)
        """
        return 1 if "@" in self.url else 0

    def _check_redirection_double_slash(self):
        """
        Checks for "//" redirection in the URL path:
        - If "//" appears after 7th position (for HTTPS), it's Phishing (1)
        - Otherwise, Legitimate (0)
        """
        protocol_end = self.url.find("://") + 3  # Find where the protocol ends
        path_start = self.url.find("//", protocol_end)
        return 1 if path_start > 7 else 0

    def _has_prefix_suffix(self):
        """
        Checks if '-' exists in the domain name:
        - Yes: Phishing (1)
        - No: Legitimate (0)
        """
        domain = urlparse(self.url).netloc
        return 1 if "-" in domain else 0

    def _classify_sub_domains(self):
        """
        Classifies the URL based on the number of dots in the domain:
        - 2 dots: Legitimate (0)
        - 3 dots: Suspicious (2)
        - >3 dots: Phishing (1)
        """
        domain = urlparse(self.url).netloc
        dot_count = domain.count(".")
        if dot_count == 2:
            return 0  # Legitimate
        elif dot_count == 3:
            return 2  # Suspicious
        else:
            return 1  # Phishing

# Example usage
if __name__ == "__main__":
    url = "http://example.com//phishing"
    extractor = feature_extractor(url)
    features = extractor.extract_features()
    print(features)

