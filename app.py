import os
import io
import math
from flask import Flask, request, jsonify, render_template
from PIL import Image, ExifTags

app = Flask(__name__)

# Configure upload limits (max 16MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_lsb_metrics(img):
    """
    Extracts LSBs from RGB channels, groups them into bytes, 
    and calculates Shannon Entropy and the ratio of 1s.
    In natural clean images, adjacent pixel LSBs are correlated (lower entropy).
    In encrypted/compressed stego images, LSBs are highly randomized (entropy near 8.0).
    """
    try:
        # Convert image to RGB to handle all formats (RGBA, Palette, etc.) uniformly
        rgb_img = img.convert('RGB')
        pixels = list(rgb_img.getdata())
        
        # Limit sampling to 120,000 pixels for fast execution
        sample_size = min(len(pixels), 120000)
        sampled_pixels = pixels[:sample_size]
        
        # Extract LSBs for each channel
        r_bits = [p[0] & 1 for p in sampled_pixels]
        g_bits = [p[1] & 1 for p in sampled_pixels]
        b_bits = [p[2] & 1 for p in sampled_pixels]
        
        def analyze_channel(bits):
            if len(bits) < 80:
                return 0.0, 0.5
            
            # Count ratio of 1s
            ones_count = sum(bits)
            ones_ratio = ones_count / len(bits)
            
            # Pack bits into 8-bit bytes to evaluate spatial entropy/randomness
            packed_bytes = []
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for bit_idx in range(8):
                    byte_val = (byte_val << 1) | bits[i + bit_idx]
                packed_bytes.append(byte_val)
            
            if not packed_bytes:
                return 0.0, ones_ratio
                
            # Calculate Shannon Entropy of the packed bytes
            counts = {}
            for b in packed_bytes:
                counts[b] = counts.get(b, 0) + 1
                
            entropy = 0.0
            total = len(packed_bytes)
            for count in counts.values():
                p = count / total
                entropy -= p * math.log2(p)
                
            return round(entropy, 4), round(ones_ratio, 4)

        r_entropy, r_ratio = analyze_channel(r_bits)
        g_entropy, g_ratio = analyze_channel(g_bits)
        b_entropy, b_ratio = analyze_channel(b_bits)
        
        return {
            "red": {"entropy": r_entropy, "ratio": r_ratio},
            "green": {"entropy": g_entropy, "ratio": g_ratio},
            "blue": {"entropy": b_entropy, "ratio": b_ratio},
            "sampled_pixels": sample_size,
            "total_pixels": len(pixels)
        }
    except Exception as e:
        return {
            "error": str(e),
            "red": {"entropy": 0.0, "ratio": 0.0},
            "green": {"entropy": 0.0, "ratio": 0.0},
            "blue": {"entropy": 0.0, "ratio": 0.0},
            "sampled_pixels": 0,
            "total_pixels": 0
        }

def calculate_chi_square_metrics(img):
    """
    Performs Westfeld's Chi-Square statistical steganalysis.
    Analyzes frequency of Pairs of Values (PoVs) like (2k, 2k+1) across R, G, B channels.
    In natural clean images, adjacent colors are asymmetric (large chi-square, p-value -> 0).
    In stego images, LSB substitution equalizes the pair frequencies (small chi-square, p-value -> 1.0).
    Uses Wilson-Hilferty approximation for chi-square CDF in pure Python.
    """
    try:
        rgb_img = img.convert('RGB')
        pixels = list(rgb_img.getdata())
        
        # Sample pixels for speed (up to 100,000)
        sample_size = min(len(pixels), 100000)
        sampled_pixels = pixels[:sample_size]
        
        r_vals = [p[0] for p in sampled_pixels]
        g_vals = [p[1] for p in sampled_pixels]
        b_vals = [p[2] for p in sampled_pixels]
        
        def run_chi_square(vals):
            # Count color occurrences (0-255)
            freq = [0] * 256
            for v in vals:
                freq[v] += 1
                
            chi_square = 0.0
            dof = 0
            
            for k in range(128):
                f2k = freq[2*k]
                f2k_plus_1 = freq[2*k + 1]
                y_k = (f2k + f2k_plus_1) / 2.0
                
                if y_k > 0:
                    dof += 1
                    # (Observed - Expected)^2 / Expected
                    # For f2k: (f2k - y_k)^2 / y_k
                    # For f2k+1: (f2k+1 - y_k)^2 / y_k
                    # Combined: (f2k - f2k_plus_1)^2 / (2 * y_k)
                    chi_square += ((f2k - f2k_plus_1) ** 2) / (2 * y_k)
            
            if dof <= 1:
                return 0.0, 0, 0.0
                
            d = dof - 1
            
            try:
                ratio = chi_square / d
                if ratio <= 0:
                    return round(chi_square, 4), d, 1.0
                # Wilson-Hilferty approximation to normal distribution
                z = ((ratio) ** (1/3) - (1 - 2 / (9 * d))) / math.sqrt(2 / (9 * d))
                p_val = 0.5 * (1.0 - math.erf(z / math.sqrt(2)))
                return round(chi_square, 4), d, round(p_val, 4)
            except Exception:
                return round(chi_square, 4), d, 0.0

        r_chi, r_dof, r_p = run_chi_square(r_vals)
        g_chi, g_dof, g_p = run_chi_square(g_vals)
        b_chi, b_dof, b_p = run_chi_square(b_vals)
        
        # Average probability
        avg_prob = round((r_p + g_p + b_p) / 3.0, 4)
        
        return {
            "red": {"chi_square": r_chi, "dof": r_dof, "p_value": r_p},
            "green": {"chi_square": g_chi, "dof": g_dof, "p_value": g_p},
            "blue": {"chi_square": b_chi, "dof": b_dof, "p_value": b_p},
            "average_stego_probability": avg_prob
        }
    except Exception as e:
        return {
            "error": str(e),
            "red": {"chi_square": 0.0, "dof": 0, "p_value": 0.0},
            "green": {"chi_square": 0.0, "dof": 0, "p_value": 0.0},
            "blue": {"chi_square": 0.0, "dof": 0, "p_value": 0.0},
            "average_stego_probability": 0.0
        }

def detect_eof_extra_data(file_bytes):
    """
    Checks for appended steganography payloads after official image EOF markers.
    - JPG ends with \xff\xd9
    - PNG ends with IEND chunk ending \x49\x45\x4E\x44\xAE\x42\x60\x82
    """
    extra_bytes = 0
    preview = ""
    suspicious = False
    
    # Check JPEG
    if file_bytes.startswith(b'\xff\xd8'):
        idx = file_bytes.rfind(b'\xff\xd9')
        if idx != -1 and idx < len(file_bytes) - 2:
            extra_bytes = len(file_bytes) - (idx + 2)
            suspicious = True
            # Extract plain text preview if readable
            preview = file_bytes[idx+2 : idx+102].decode('utf-8', errors='ignore').strip()
            
    # Check PNG
    elif file_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        idx = file_bytes.rfind(b'IEND')
        if idx != -1:
            # PNG IEND chunk has 4 bytes type, 4 bytes CRC. Standard PNG ends 8 bytes after IEND start
            chunk_end = idx + 8
            if chunk_end < len(file_bytes):
                extra_bytes = len(file_bytes) - chunk_end
                suspicious = True
                preview = file_bytes[chunk_end : chunk_end+102].decode('utf-8', errors='ignore').strip()
                
    # Filter non-printable characters for the preview
    clean_preview = "".join(ch if (32 <= ord(ch) <= 126 or ch in "\r\n\t") else "." for ch in preview)
    if len(clean_preview) > 60:
        clean_preview = clean_preview[:60] + "..."
        
    return {
        "detected": suspicious,
        "extra_bytes": extra_bytes,
        "preview": clean_preview if suspicious else ""
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'image' not in request.files:
        return jsonify({"success": False, "error": "No image file provided."}), 400
        
    file = request.files['image']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected."}), 400
        
    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Unsupported file format. Please upload a JPG, JPEG, or PNG image."}), 400
        
    try:
        # Read file bytes in memory
        file_bytes = file.read()
        
        # EOF Analysis
        eof_report = detect_eof_extra_data(file_bytes)
        
        # Load image via Pillow
        img = Image.open(io.BytesIO(file_bytes))
        
        # Basic Image Metadata
        metadata = {
            "filename": file.filename,
            "format": img.format,
            "mode": img.mode,
            "dimensions": f"{img.size[0]} x {img.size[1]} px",
            "file_size_kb": round(len(file_bytes) / 1024, 2)
        }
        
        # Extract EXIF tag values if present
        exif_tags = {}
        if hasattr(img, '_getexif') and img._getexif() is not None:
            for tag, val in img._getexif().items():
                tag_name = ExifTags.TAGS.get(tag, tag)
                if not isinstance(val, bytes):
                    exif_tags[str(tag_name)] = str(val)
        metadata["exif"] = exif_tags
        metadata["has_exif"] = len(exif_tags) > 0
        
        # Extract embedded comments/software metadata from PNG text chunks
        text_metadata = {}
        for key, val in img.info.items():
            if isinstance(val, (str, int, float)):
                text_metadata[str(key)] = str(val)
        metadata["text_chunks"] = text_metadata
        metadata["has_text_chunks"] = len(text_metadata) > 0
        
        # LSB Analysis
        lsb_report = calculate_lsb_metrics(img)
        
        # Statistical Chi-Square Analysis
        chi_report = calculate_chi_square_metrics(img)
        
        # Verdict calculation
        verdict = "CLEAN"
        reasons = []
        
        # Check EOF anomaly
        if eof_report["detected"]:
            verdict = "SUSPICIOUS"
            reasons.append(f"Detected {eof_report['extra_bytes']} bytes of trailing data appended after official image EOF marker.")
            
        # Check LSB anomalies: in randomized encoding (like encryption or compression),
        # LSB entropy gets extremely close to 8.0 (perfect randomness), and ones ratio resides very near 0.5.
        # Generally, natural images have LSB entropy of 7.0 - 7.8 due to local spatial correlation.
        threshold_entropy = 7.97
        suspicious_lsb_channels = []
        for ch, data in [("Red", lsb_report["red"]), ("Green", lsb_report["green"]), ("Blue", lsb_report["blue"])]:
            if data["entropy"] >= threshold_entropy:
                suspicious_lsb_channels.append(ch)
                
        if suspicious_lsb_channels:
            verdict = "SUSPICIOUS"
            channels_str = ", ".join(suspicious_lsb_channels)
            reasons.append(f"Highly randomized LSB noise detected in channels: {channels_str} (Entropy >= {threshold_entropy}). This is characteristic of encrypted/compressed payload embedding.")
            
        # Check Chi-Square anomalies
        suspicious_chi_channels = []
        for ch, data in [("Red", chi_report["red"]), ("Green", chi_report["green"]), ("Blue", chi_report["blue"])]:
            if data["p_value"] >= 0.95:
                suspicious_chi_channels.append(f"{ch} (p-value: {data['p_value']})")
                
        if suspicious_chi_channels:
            verdict = "SUSPICIOUS"
            channels_str = ", ".join(suspicious_chi_channels)
            reasons.append(f"Chi-Square statistical stego-anomaly detected in channels: {channels_str}. Equal-frequency PoV distributions strongly indicate LSB substitution.")
            
        # Make a final response object
        response = {
            "success": True,
            "verdict": verdict,
            "reasons": reasons if reasons else ["No clear steganographic anomalies or trailing payloads detected in the structure."],
            "metadata": metadata,
            "lsb_analysis": lsb_report,
            "chi_analysis": chi_report,
            "eof_analysis": eof_report
        }
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to analyze image: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
