from flask import Flask, render_template, request
from extractor import feature_extractor
import pickle

# Load the pre-trained model
model_filename = 'finalized_model.sav'
loaded_model = pickle.load(open(model_filename, 'rb'))

# Initialize Flask app
app = Flask(__name__)

# Predictor function (adapted from your original code)
def predictor(features):
    """
    Predict whether the URL is spoofed or legitimate using the loaded model.
    """
    features_df = features[["long_url", "having_@_symbol", "redirection_//_symbol", 
                             "prefix_suffix_seperation", "sub_domains"]]
    preds = loaded_model.predict(features_df)
    score = loaded_model.predict_proba(features_df)
    if preds[0] == 0:
        result = "Spoofed webpage: Yes"
    else:
        result = "Spoofed webpage: No"
    confidence = f"Confidence score: {score[0][1]:.2f}"
    return result, confidence

@app.route("/", methods=["GET", "POST"])
def index():
    """
    Renders the home page with a form to input URL and displays the results.
    """
    result = None
    confidence = None

    if request.method == "POST":
        # Get the URL from the form
        url = request.form.get("url_input")

        # Extract features using the feature_extractor module
        feature_extractor_obj = feature_extractor(url)
        features_dict = feature_extractor_obj.extract_features()

        # Prepare features for the model
        import pandas as pd
        features_df = pd.DataFrame([features_dict])  # Single-row DataFrame

        # Predict using the model
        result, confidence = predictor(features_df)

    return render_template("trial.html", result=result, confidence=confidence)

if __name__ == "__main__":
    app.run(debug=True)
