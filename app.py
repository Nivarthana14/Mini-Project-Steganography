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
    Extracts LSBs from RGBA or RGB channels, groups them into bytes, 
    calculates Shannon Entropy (globally and in 1KB local blocks),
    scans for unencrypted ASCII strings (global, leading, and prefix),
    and checks for tool signatures (OpenStego).
    """
    try:
        # Check if the image has an alpha channel
        has_alpha = img.mode in ('RGBA', 'LA', 'PA')
        if has_alpha:
            img_normalized = img.convert('RGBA')
        else:
            img_normalized = img.convert('RGB')
            
        pixels = list(img_normalized.getdata())
        
        # Limit sampling to 120,000 pixels for fast execution
        sample_size = min(len(pixels), 120000)
        sampled_pixels = pixels[:sample_size]
        
        # Extract LSBs for each channel
        r_bits = [p[0] & 1 for p in sampled_pixels]
        g_bits = [p[1] & 1 for p in sampled_pixels]
        b_bits = [p[2] & 1 for p in sampled_pixels]
        a_bits = [p[3] & 1 for p in sampled_pixels] if has_alpha else []
        
        def analyze_channel(bits):
            if len(bits) < 80:
                return 0.0, 0.5, 0.0, [], None, []
            
            ones_count = sum(bits)
            ones_ratio = ones_count / len(bits)
            
            # Pack bits into 8-bit bytes
            packed_bytes = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for bit_idx in range(8):
                    byte_val = (byte_val << 1) | bits[i + bit_idx]
                packed_bytes.append(byte_val)
            
            if not packed_bytes:
                return 0.0, ones_ratio, 0.0, [], None, []
                
            # Calculate Shannon Entropy of the packed bytes
            counts = {}
            for b in packed_bytes:
                counts[b] = counts.get(b, 0) + 1
                
            entropy = 0.0
            total = len(packed_bytes)
            for count in counts.values():
                p = count / total
                entropy -= p * math.log2(p)
                
            # Local Block Entropy Analysis (blocks of 1,000 bytes)
            max_block_entropy = 0.0
            block_size = 1000
            if len(packed_bytes) >= block_size:
                for start_idx in range(0, len(packed_bytes) - block_size + 1, block_size):
                    block = packed_bytes[start_idx : start_idx + block_size]
                    b_counts = {}
                    for b in block:
                        b_counts[b] = b_counts.get(b, 0) + 1
                    b_entropy = 0.0
                    b_total = len(block)
                    for count in b_counts.values():
                        p = count / b_total
                        b_entropy -= p * math.log2(p)
                    if b_entropy > max_block_entropy:
                        max_block_entropy = b_entropy
            else:
                max_block_entropy = entropy
                
            # ASCII scanners:
            # 1. Global (len >= 12)
            global_texts = []
            current = []
            for b in packed_bytes:
                if 32 <= b <= 126 or b in (9, 10, 13):
                    current.append(chr(b))
                else:
                    if len(current) >= 12:
                        global_texts.append("".join(current))
                    current = []
            if len(current) >= 12:
                global_texts.append("".join(current))
                
            # 2. Leading (starts at 0, len >= 5)
            leading_text = None
            seq = []
            for b in packed_bytes:
                if 32 <= b <= 126 or b in (9, 10, 13):
                    seq.append(chr(b))
                else:
                    break
            if len(seq) >= 5:
                leading_text = "".join(seq)
                
            # 3. Prefix (starts within first 50, len >= 8)
            prefix_texts = []
            current = []
            for b in packed_bytes[:50]:
                if 32 <= b <= 126 or b in (9, 10, 13):
                    current.append(chr(b))
                else:
                    if len(current) >= 8:
                        prefix_texts.append("".join(current))
                    current = []
            if len(current) >= 8:
                prefix_texts.append("".join(current))
            
            return round(entropy, 4), round(ones_ratio, 4), round(max_block_entropy, 4), global_texts, leading_text, prefix_texts

        r_entropy, r_ratio, r_max_block, r_texts, r_leading, r_prefix = analyze_channel(r_bits)
        g_entropy, g_ratio, g_max_block, g_texts, g_leading, g_prefix = analyze_channel(g_bits)
        b_entropy, b_ratio, b_max_block, b_texts, b_leading, b_prefix = analyze_channel(b_bits)
        
        if has_alpha:
            a_entropy, a_ratio, a_max_block, a_texts, a_leading, a_prefix = analyze_channel(a_bits)
        else:
            a_entropy, a_ratio, a_max_block, a_texts, a_leading, a_prefix = 0.0, 0.5, 0.0, [], None, []
            
        # Scan for interleaved unencrypted messages (standard across R, G, B)
        interleaved_bits = []
        limit = min(len(r_bits), len(g_bits), len(b_bits))
        for i in range(limit):
            interleaved_bits.append(r_bits[i])
            interleaved_bits.append(g_bits[i])
            interleaved_bits.append(b_bits[i])
            
        interleaved_bytes = bytearray()
        for i in range(0, min(len(interleaved_bits), 240000) - 7, 8):
            b = 0
            for bit_idx in range(8):
                b = (b << 1) | interleaved_bits[i + bit_idx]
            interleaved_bytes.append(b)
            
        # Scan interleaved
        interleaved_global_texts = []
        current = []
        for b in interleaved_bytes:
            if 32 <= b <= 126 or b in (9, 10, 13):
                current.append(chr(b))
            else:
                if len(current) >= 12:
                    interleaved_global_texts.append("".join(current))
                current = []
        if len(current) >= 12:
            interleaved_global_texts.append("".join(current))
            
        interleaved_leading_text = None
        seq = []
        for b in interleaved_bytes:
            if 32 <= b <= 126 or b in (9, 10, 13):
                seq.append(chr(b))
            else:
                break
        if len(seq) >= 5:
            interleaved_leading_text = "".join(seq)
            
        interleaved_prefix_texts = []
        current = []
        for b in interleaved_bytes[:50]:
            if 32 <= b <= 126 or b in (9, 10, 13):
                current.append(chr(b))
            else:
                if len(current) >= 8:
                    interleaved_prefix_texts.append("".join(current))
                current = []
        if len(current) >= 8:
            interleaved_prefix_texts.append("".join(current))
        
        # Check OpenStego signature in interleaved bytes
        openstego_detected = False
        if len(interleaved_bytes) >= 4 and interleaved_bytes[:4] == b"OSTG":
            openstego_detected = True
            
        report = {
            "red": {"entropy": r_entropy, "ratio": r_ratio, "max_block_entropy": r_max_block, "extracted_texts": r_texts, "leading_text": r_leading, "prefix_texts": r_prefix},
            "green": {"entropy": g_entropy, "ratio": g_ratio, "max_block_entropy": g_max_block, "extracted_texts": g_texts, "leading_text": g_leading, "prefix_texts": g_prefix},
            "blue": {"entropy": b_entropy, "ratio": b_ratio, "max_block_entropy": b_max_block, "extracted_texts": b_texts, "leading_text": b_leading, "prefix_texts": b_prefix},
            "sampled_pixels": sample_size,
            "total_pixels": len(pixels),
            "has_alpha": has_alpha,
            "interleaved_global_texts": interleaved_global_texts,
            "interleaved_leading_text": interleaved_leading_text,
            "interleaved_prefix_texts": interleaved_prefix_texts,
            "openstego_detected": openstego_detected
        }
        if has_alpha:
            report["alpha"] = {"entropy": a_entropy, "ratio": a_ratio, "max_block_entropy": a_max_block, "extracted_texts": a_texts, "leading_text": a_leading, "prefix_texts": a_prefix}
            
        return report
    except Exception as e:
        return {
            "error": str(e),
            "red": {"entropy": 0.0, "ratio": 0.0, "max_block_entropy": 0.0, "extracted_texts": [], "leading_text": None, "prefix_texts": []},
            "green": {"entropy": 0.0, "ratio": 0.0, "max_block_entropy": 0.0, "extracted_texts": [], "leading_text": None, "prefix_texts": []},
            "blue": {"entropy": 0.0, "ratio": 0.0, "max_block_entropy": 0.0, "extracted_texts": [], "leading_text": None, "prefix_texts": []},
            "sampled_pixels": 0,
            "total_pixels": 0,
            "has_alpha": False,
            "interleaved_global_texts": [],
            "interleaved_leading_text": None,
            "interleaved_prefix_texts": [],
            "openstego_detected": False
        }

def calculate_chi_square_metrics(img):
    """
    Performs Westfeld's Chi-Square statistical steganalysis over multiple sub-ranges
    (progressively first 5,000, 20,000, and up to 100,000 pixels) to detect partial/sequential stego.
    Supports Alpha channel when present.
    """
    try:
        has_alpha = img.mode in ('RGBA', 'LA', 'PA')
        if has_alpha:
            img_normalized = img.convert('RGBA')
        else:
            img_normalized = img.convert('RGB')
            
        pixels = list(img_normalized.getdata())
        
        # Sample pixels for speed (up to 100,000)
        sample_size = min(len(pixels), 100000)
        sampled_pixels = pixels[:sample_size]
        
        r_vals = [p[0] for p in sampled_pixels]
        g_vals = [p[1] for p in sampled_pixels]
        b_vals = [p[2] for p in sampled_pixels]
        a_vals = [p[3] for p in sampled_pixels] if has_alpha else []
        
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
                    chi_square += ((f2k - f2k_plus_1) ** 2) / (2 * y_k)
            
            if dof <= 1:
                return 0.0, 0, 0.0
                
            d = dof - 1
            
            try:
                ratio = chi_square / d
                if ratio <= 0:
                    return round(chi_square, 4), d, 1.0
                z = ((ratio) ** (1/3) - (1 - 2 / (9 * d))) / math.sqrt(2 / (9 * d))
                p_val = 0.5 * (1.0 - math.erf(z / math.sqrt(2)))
                return round(chi_square, 4), d, round(p_val, 4)
            except Exception:
                return round(chi_square, 4), d, 0.0

        def get_max_progressive_p_value(vals):
            sizes = [5000, 20000, len(vals)]
            max_p = 0.0
            chosen_chi = 0.0
            chosen_dof = 0
            
            for sz in sizes:
                if sz > len(vals):
                    continue
                sub_vals = vals[:sz]
                chi, dof, p = run_chi_square(sub_vals)
                if p > max_p:
                    max_p = p
                    chosen_chi = chi
                    chosen_dof = dof
            
            # Fallback if image is very small or no size matched
            if max_p == 0.0 and vals:
                chosen_chi, chosen_dof, max_p = run_chi_square(vals)
                
            return chosen_chi, chosen_dof, max_p

        r_chi, r_dof, r_p = get_max_progressive_p_value(r_vals)
        g_chi, g_dof, g_p = get_max_progressive_p_value(g_vals)
        b_chi, b_dof, b_p = get_max_progressive_p_value(b_vals)
        
        if has_alpha:
            a_chi, a_dof, a_p = get_max_progressive_p_value(a_vals)
            avg_prob = round((r_p + g_p + b_p + a_p) / 4.0, 4)
        else:
            avg_prob = round((r_p + g_p + b_p) / 3.0, 4)
            
        report = {
            "red": {"chi_square": r_chi, "dof": r_dof, "p_value": r_p},
            "green": {"chi_square": g_chi, "dof": g_dof, "p_value": g_p},
            "blue": {"chi_square": b_chi, "dof": b_dof, "p_value": b_p},
            "average_stego_probability": avg_prob,
            "has_alpha": has_alpha
        }
        if has_alpha:
            report["alpha"] = {"chi_square": a_chi, "dof": a_dof, "p_value": a_p}
            
        return report
    except Exception as e:
        return {
            "error": str(e),
            "red": {"chi_square": 0.0, "dof": 0, "p_value": 0.0},
            "green": {"chi_square": 0.0, "dof": 0, "p_value": 0.0},
            "blue": {"chi_square": 0.0, "dof": 0, "p_value": 0.0},
            "average_stego_probability": 0.0,
            "has_alpha": False
        }

def detect_eof_extra_data(file_bytes):
    """
    Checks for appended steganography payloads after official image EOF markers.
    - JPG ends with \xff\xd9
    - PNG ends with IEND chunk ending \x49\x45\x4E\x44\xAE\x42\x60\x82
    """
    extra_bytes = 0
    preview = ""
    clean = False
    
    # Check JPEG
    if file_bytes.startswith(b'\xff\xd8'):
        idx = file_bytes.rfind(b'\xff\xd9')
        if idx != -1 and idx < len(file_bytes) - 2:
            extra_bytes = len(file_bytes) - (idx + 2)
            clean = True
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
                clean = True
                preview = file_bytes[chunk_end : chunk_end+102].decode('utf-8', errors='ignore').strip()
                
    # Filter non-printable characters for the preview
    clean_preview = "".join(ch if (32 <= ord(ch) <= 126 or ch in "\r\n\t") else "." for ch in preview)
    if len(clean_preview) > 60:
        clean_preview = clean_preview[:60] + "..."
        
    return {
        "detected": clean,
        "extra_bytes": extra_bytes,
        "preview": clean_preview if clean else ""
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
        verdict = "clean"
        reasons = []
        
        # 1. Check EOF anomaly
        if eof_report["detected"]:
            verdict = "suspicious"
            reasons.append(f"Detected {eof_report['extra_bytes']} bytes of trailing data appended after official image EOF marker.")
            
        # 2. Check metadata anomalies
        suspicious_metadata = []
        stego_keywords = {"steg", "stego", "steghide", "stegosuite", "outguess", "openstego", "covert", "embed", "hidden", "secret", "payload"}
        
        # Check EXIF tags
        for tag, val in exif_tags.items():
            tag_lower = str(tag).lower()
            val_lower = str(val).lower()
            for word in stego_keywords:
                if word in tag_lower or word in val_lower:
                    suspicious_metadata.append(f"EXIF tag '{tag}' contains suspicious term '{word}': '{val}'")
                    break
                    
        # Check PNG text chunks
        for key, val in text_metadata.items():
            key_lower = str(key).lower()
            val_lower = str(val).lower()
            for word in stego_keywords:
                if word in key_lower or word in val_lower:
                    suspicious_metadata.append(f"PNG text chunk '{key}' contains suspicious term '{word}': '{val}'")
                    break
                    
        if suspicious_metadata:
            verdict = "suspicious"
            reasons.extend(suspicious_metadata)

        # 3. Check LSB anomalies
        # We check both overall entropy AND local block entropy.
        threshold_entropy = 7.95
        threshold_block_entropy = 7.95
        
        channels_to_check = [("Red", lsb_report["red"]), ("Green", lsb_report["green"]), ("Blue", lsb_report["blue"])]
        if lsb_report.get("has_alpha"):
            channels_to_check.append(("Alpha", lsb_report["alpha"]))
            
        suspicious_lsb_channels = []
        for ch, data in channels_to_check:
            # Check overall entropy
            if data["entropy"] >= threshold_entropy:
                suspicious_lsb_channels.append(f"{ch} (Overall Entropy: {data['entropy']})")
            # Check block entropy
            elif data.get("max_block_entropy", 0) >= threshold_block_entropy:
                suspicious_lsb_channels.append(f"{ch} (Max Block Entropy: {data['max_block_entropy']})")
                
        if suspicious_lsb_channels:
            verdict = "suspicious"
            channels_str = ", ".join(suspicious_lsb_channels)
            reasons.append(f"Highly randomized LSB noise detected in channels: {channels_str}. This is characteristic of encrypted/compressed payload embedding.")

        # 4. Check unencrypted LSB plain-text messages or tool signatures
        # Check OpenStego signature
        if lsb_report.get("openstego_detected"):
            verdict = "suspicious"
            reasons.append("OpenStego steganography tool signature ('OSTG') detected in LSB bitstream.")
            
        # Check per-channel and interleaved extracted ASCII strings
        all_extracted_texts = []
        text_sources = []
        
        for ch, data in channels_to_check:
            if data.get("extracted_texts"):
                text_sources.extend(data["extracted_texts"])
            if data.get("leading_text"):
                text_sources.append(data["leading_text"])
            if data.get("prefix_texts"):
                text_sources.extend(data["prefix_texts"])
                
        if lsb_report.get("interleaved_global_texts"):
            text_sources.extend(lsb_report["interleaved_global_texts"])
        if lsb_report.get("interleaved_leading_text"):
            text_sources.append(lsb_report["interleaved_leading_text"])
        if lsb_report.get("interleaved_prefix_texts"):
            text_sources.extend(lsb_report["interleaved_prefix_texts"])
            
        for text in text_sources:
            clean_text = text.strip()
            if len(clean_text) >= 5 and clean_text not in all_extracted_texts:
                # If length is less than 8, require at least one vowel/space to filter random noise
                if len(clean_text) < 8:
                    vowels = set("aeiouAEIOU ")
                    if not any(c in vowels for c in clean_text):
                        continue
                all_extracted_texts.append(clean_text)
                
        if all_extracted_texts:
            verdict = "suspicious"
            preview_texts = [f"'{t[:50]}...'" if len(t) > 50 else f"'{t}'" for t in all_extracted_texts[:3]]
            reasons.append(f"Readable unencrypted plain-text message extracted from LSB: {', '.join(preview_texts)}")

        # 5. Check Chi-Square anomalies
        chi_channels_to_check = [("Red", chi_report["red"]), ("Green", chi_report["green"]), ("Blue", chi_report["blue"])]
        if chi_report.get("has_alpha"):
            chi_channels_to_check.append(("Alpha", chi_report["alpha"]))
            
        suspicious_chi_channels = []
        for ch, data in chi_channels_to_check:
            if data["p_value"] >= 0.95:
                suspicious_chi_channels.append(f"{ch} (p-value: {data['p_value']})")
                
        if suspicious_chi_channels:
            verdict = "suspicious"
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
