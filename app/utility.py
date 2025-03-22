import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim
from PIL import Image, ImageChops, ImageEnhance
import matplotlib.pyplot as plt
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import openai



def preprocess_image(image_path, size=(800, 600)):
    """
    Preprocesses the Aadhaar image by resizing, converting to grayscale, 
    and applying Gaussian blur to reduce noise.
    
    Args:
    - image_path (str): Path to the image.
    - size (tuple): Target size for resizing.
    
    Returns:
    - Processed grayscale image.
    """
    img = cv2.imread(image_path)
    img = cv2.resize(img, size)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (3, 3), 0)  # Reduce noise
    return gray

def align_images(reference_img, test_img):
    """
    Aligns the test Aadhaar card with the reference template using ORB feature matching.
    
    Args:
    - reference_img (numpy.ndarray): Reference Aadhaar template.
    - test_img (numpy.ndarray): Test Aadhaar image.
    
    Returns:
    - Aligned test image.
    """
    orb = cv2.ORB_create(500)
    keypoints1, descriptors1 = orb.detectAndCompute(reference_img, None)
    keypoints2, descriptors2 = orb.detectAndCompute(test_img, None)

    matcher = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = matcher.match(descriptors1, descriptors2)
    matches = sorted(matches, key=lambda x: x.distance)

    if len(matches) < 10:
        return test_img  # Return original if not enough matches

    src_pts = np.float32([keypoints1[m.queryIdx].pt for m in matches]).reshape(-1, 1, 2)
    dst_pts = np.float32([keypoints2[m.trainIdx].pt for m in matches]).reshape(-1, 1, 2)

    matrix, _ = cv2.findHomography(dst_pts, src_pts, cv2.RANSAC, 5.0)
    
    if matrix is None:
        return test_img  # If no transformation found, return as is

    aligned_img = cv2.warpPerspective(test_img, matrix, (reference_img.shape[1], reference_img.shape[0]))
    return aligned_img

def apply_ela(image_path, quality=90):
    """
    Applies Error Level Analysis (ELA) to detect tampering.
    
    Args:
    - image_path (str): Path to the image.
    - quality (int): JPEG compression quality.
    
    Returns:
    - float: Normalized ELA forgery score.
    """
    original = Image.open(image_path).convert("RGB")
    temp_path = "temp_ela.jpg"
    original.save(temp_path, "JPEG", quality=quality)

    compressed = Image.open(temp_path)
    ela_image = ImageChops.difference(original, compressed)

    extrema = ela_image.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    scale = 255.0 / max_diff if max_diff > 0 else 1
    ela_image = ImageEnhance.Brightness(ela_image).enhance(scale)

    ela_array = np.array(ela_image, dtype=np.float32) / 255.0
    mse_score = np.mean(ela_array ** 2)

    normalized_score = mse_score / 0.1
    return min(normalized_score, 1.0)

def calculate_ssim(image1, image2):
    """
    Computes Structural Similarity Index (SSIM) to measure similarity.
    
    Args:
    - image1 (numpy.ndarray): First image.
    - image2 (numpy.ndarray): Second image.
    
    Returns:
    - float: SSIM score.
    """
    score, _ = ssim(image1, image2, full=True)
    return score

def detect_aadhaar_forgery(reference_path, test_path):
    """
    Detects Aadhaar forgery by comparing the structure of a given Aadhaar card
    with a reference template.
    
    Args:
    - reference_path (str): Path to reference Aadhaar image.
    - test_path (str): Path to the Aadhaar image being tested.
    
    Returns:
    - dict: Results including SSIM score and ELA score.
    """
    # Step 1: Preprocess Images
    reference_img = preprocess_image(reference_path)
    test_img = preprocess_image(test_path)

    # Step 2: Align Images
    test_img = align_images(reference_img, test_img)

    # Step 3: Compute Structural Similarity Index (SSIM)
    ssim_score = calculate_ssim(reference_img, test_img)

    # Step 4: Apply Error Level Analysis (ELA)
    ela_score = apply_ela(test_path)

    # Step 5: Decision Making
    forgery_detected = (ssim_score < 0.75) or (ela_score > 0.2)

    return {
        "ssim_score": round(ssim_score, 4),
        "ela_score": round(ela_score, 4),
        "forgery_detected": forgery_detected
    }

def load_image_as_numpy(image_path):
    """
    Loads an image using PIL and converts it to a NumPy array.
    
    Parameters:
        image_path (str): Path to the image file.
    
    Returns:
        np.ndarray: Image as a NumPy array.
    """
    image = Image.open(image_path)  # Load image with PIL
    image = image.convert("RGB")  # Ensure it's in RGB format
    return np.array(image)  # Convert to NumPy array

def analyze_image_difference(original_img_path, tampered_img_path):
    """
    Compares two images and highlights differences.
    
    Parameters:
        original_img_path (str): Path to the original image.
        tampered_img_path (str): Path to the possibly tampered image.
    
    Returns:
        None (Displays the differences).
    """
    # Load images as NumPy arrays
    img1 = load_image_as_numpy(original_img_path)
    img2 = load_image_as_numpy(tampered_img_path)

    # Resize tampered image to match original
    img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

    # Convert to grayscale
    gray1 = cv2.cvtColor(img1, cv2.COLOR_RGB2GRAY)
    gray2 = cv2.cvtColor(img2, cv2.COLOR_RGB2GRAY)

    # Compute absolute difference
    diff = cv2.absdiff(gray1, gray2)

    # Apply threshold to detect changes
    _, threshold_diff = cv2.threshold(diff, 30, 255, cv2.THRESH_BINARY)

    # Highlight differences on original image
    highlighted_diff = img1.copy()
    highlighted_diff[threshold_diff == 255] = [255, 0, 0]  # Mark changes in Red

    # Display results
    plt.figure(figsize=(12, 6))
    
    plt.subplot(1, 3, 1)
    plt.imshow(img1)
    plt.title("Original Image")
    plt.subplot(1, 3, 2)
    plt.imshow(img2)
    plt.title("Tampered Image")
    plt.subplot(1, 3, 3)
    plt.imshow(highlighted_diff)
    plt.title("Differences Highlighted")
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Define the media folder path
    MEDIA_DIR = os.path.join(BASE_DIR, "media")

    # Ensure the media directory exists
    os.makedirs(MEDIA_DIR, exist_ok=True)

    # Save the plot in the media folder
    save_path = os.path.join(MEDIA_DIR, "Q.png")
    plt.savefig(save_path)
    return 'Q.png'


def preprocess_data(df):
    """Preprocess the dataset for anomaly detection."""
    df['Date'] = pd.to_datetime(df['Date'], errors='coerce')  # Convert date to datetime format
    df['Days_Since_First'] = (df['Date'] - df['Date'].min()).dt.days  # Convert date to numerical value
    
    # Selecting features for the model
    feature_columns = ['Amount', 'Balance', 'Days_Since_First']
    df_features = df[feature_columns].dropna()  # Drop NaN values

    return df, df_features

def train_anomaly_detection_model(data):
    """Train an optimized Isolation Forest model."""
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(data)

    model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, bootstrap=True, n_jobs=-1)
    model.fit(X_scaled)

    return model, scaler

def detect_forged_transactions(df, data, model, scaler):
    """Detect forged transactions and add the 'is_forged' label."""
    X_scaled = scaler.transform(data)
    predictions = model.predict(X_scaled)

    # Isolation Forest labels anomalies as -1
    df.loc[data.index, 'is_forged'] = (predictions == -1).astype(int)
    
    return df

def bank_statement_main(df):
    # Preprocess data
    df, df_features = preprocess_data(df)

    # Train model
    model, scaler = train_anomaly_detection_model(df_features)

    # Detect forged transactions
    results = detect_forged_transactions(df, df_features, model, scaler)

    # Save results to CSV in the current directory
    output_file = "detected_forged_transactions.csv"
    results.to_csv(output_file, index=False)


    print(f"Detection complete. {results['is_forged'].sum()} forged transactions detected.")
    print(f"Results saved in '{output_file}'")

    return results


# def get_llm_judgment(forgery_result):
#     prompt = f"""
#     Analyze the following Aadhaar forgery detection results:

#     Forgery Analysis:
#     - SSIM Score: {forgery_result['ssim_score']}
#     - ELA Score: {forgery_result['ela_score']}
#     - Forgery Detected: {forgery_result['forgery_detected']}

#     Based on the analysis, provide a clear judgment:
#     1. Is the Aadhaar card likely genuine or fake?
#     2. How confident are you in this assessment?
#     3. If there are inconsistencies, what are the possible reasons?
#     """
    
#     response = openai.ChatCompletion.create(
#         model="gpt-4",
#         messages=[{"role": "system", "content": "You are an expert in document verification and forgery detection."},
#                   {"role": "user", "content": prompt}]
#     )
#     return response['choices'][0]['message']['content']