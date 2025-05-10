import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import re
import base64
import requests
import json
from supabase import create_client, Client
import uuid
import datetime 

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'mykey2025'

# --- Supabase Configuration ---
SUPABASE_URL: str = "https://thlugzhimjoyfhihuefy.supabase.co"
SUPABASE_KEY: str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRobHVnemhpbWpveWZoaWh1ZWZ5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDY2Mjk4NDIsImV4cCI6MjA2MjIwNTg0Mn0.5HsWCZLJ1lTaEvXNGfgLMaTOBhSUUQLFdbziGFyjdYs"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Gemini API Configuration ---
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'AIzaSyBU0nYJ79vuTX5CbJReS43Ygz96l_zrpgs') # IMPORTANT: Use your actual key or env var
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent"


# --- Routes for authentication (Keep as is) ---
@app.route('/')
def home():
    access_token = session.get('supabase_access_token')
    if access_token:
        try:
            user_response = supabase.auth.get_user(access_token)
            if user_response.user:
                session['user_id'] = user_response.user.id
                session['user_email'] = user_response.user.email
                profile_res = supabase.table('profiles').select('full_name').eq('id', user_response.user.id).maybe_single().execute()
                if profile_res.data and profile_res.data.get('full_name'):
                    session['user_full_name'] = profile_res.data['full_name']
                else:
                    session['user_full_name'] = user_response.user.email
                return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Token verification error on home: {e}")
            session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        errors = {}
        if not full_name: errors['full_name'] = "Full name is required."
        elif not (2 <= len(full_name) <= 100): errors['full_name'] = "Full name must be between 2 and 100 characters."
        elif not re.match(r"^[A-Za-z\s.'\-]+$", full_name): errors['full_name'] = "Full name contains invalid characters. Only letters, spaces, and ' . - are allowed."
        if not email: errors['email'] = "Email is required."
        elif not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email): errors['email'] = "Invalid email format."
        elif len(email) > 255: errors['email'] = "Email is too long."
        if not password: errors['password'] = "Password is required."
        elif len(password) < 6: errors['password'] = "Password must be at least 6 characters long."
        elif not re.match(r"^[A-Za-z\d@$!%*?&.\s]{6,}$", password): errors['password'] = "Password contains invalid characters or is too short."

        if errors:
            for field, message in errors.items(): flash(f"{message}", "danger")
            return render_template('register.html', form_data=request.form)
        try:
            auth_response = supabase.auth.sign_up({"email": email, "password": password, "options": {"data": {"full_name": full_name}}})
            if auth_response.user:
                if not auth_response.session and auth_response.user.id: flash("Registration successful! Please check your email to confirm your account.", "success")
                else: flash("Registration successful! Please login.", "success")
                return redirect(url_for('login'))
            elif hasattr(auth_response, 'error') and auth_response.error: flash(f"{auth_response.error.message}", "danger")
            else: flash("An unknown error occurred during registration.", "danger")
            return render_template('register.html', form_data=request.form)
        except Exception as e:
            flash(f"An unexpected error occurred: {str(e)}", "error")
            print(f"Registration Exception: {e}")
            return render_template('register.html', form_data=request.form)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash("Email and password are required.", "warning")
            return render_template('login.html')
        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email.lower(), "password": password})
            if auth_response.user and auth_response.session:
                session['supabase_access_token'] = auth_response.session.access_token
                session['supabase_refresh_token'] = auth_response.session.refresh_token
                session['user_id'] = auth_response.user.id
                session['user_email'] = auth_response.user.email
                profile_res = supabase.table('profiles').select('full_name').eq('id', auth_response.user.id).maybe_single().execute()
                if profile_res.data and profile_res.data.get('full_name'): session['user_full_name'] = profile_res.data['full_name']
                elif auth_response.user.user_metadata and auth_response.user.user_metadata.get('full_name'): session['user_full_name'] = auth_response.user.user_metadata.get('full_name')
                else: session['user_full_name'] = auth_response.user.email
                flash(f"Welcome back, {session['user_full_name']}!", "success")
                return redirect(url_for('dashboard'))
            elif hasattr(auth_response, 'error') and auth_response.error: flash(f"{auth_response.error.message}", "danger")
            else: flash("Login failed. Please check your credentials or confirm your email.", "danger")
        except Exception as e:
            flash(f"An unexpected error occurred: {str(e)}", "error")
            print(f"Login Exception: {e}")
    return render_template('login.html')

@app.before_request
def set_supabase_auth_from_session():
    access_token = session.get('supabase_access_token')
    if access_token:
        try: supabase.auth.set_session(access_token, session.get('supabase_refresh_token'))
        except Exception as e:
            print(f"Error setting Supabase session: {e}")
            session.pop('supabase_access_token', None)
            session.pop('supabase_refresh_token', None)
            session.pop('user_id', None)

def is_user_authenticated():
    access_token = session.get('supabase_access_token')
    if not access_token: return False
    try:
        user_info = supabase.auth.get_user(access_token)
        if user_info.user:
            session['user_id'] = user_info.user.id
            return True
        return False
    except Exception as e:
        print(f"User authentication check failed: {e}")
        session.clear()
        return False

@app.route('/dashboard')
def dashboard():
    if is_user_authenticated():
        if 'user_full_name' not in session and 'user_id' in session:
            profile_res = supabase.table('profiles').select('full_name').eq('id', session['user_id']).maybe_single().execute()
            if profile_res.data and profile_res.data.get('full_name'): session['user_full_name'] = profile_res.data['full_name']
            else: session['user_full_name'] = session.get('user_email', 'User')
        
        script_load_time = datetime.datetime.now() # Get current datetime
        return render_template('home.html', 
                               user_full_name=session.get('user_full_name'),
                               SCRIPT_LOAD_TIME=script_load_time) # Pass it to the template
    flash("Please login to access the dashboard.", "warning")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    access_token = session.get('supabase_access_token')
    if access_token:
        try: supabase.auth.sign_out()
        except Exception as e: print(f"Error during Supabase sign out: {e}")
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/index')
def index_page():
    if is_user_authenticated(): return redirect(url_for('dashboard'))
    return redirect(url_for('login'))
# --- End of auth routes ---

def encode_image_to_base64(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def analyze_image_with_gemini(image_path):
    try:
        base64_image = encode_image_to_base64(image_path)
        payload = {
            "contents": [{
                "parts": [
                    {"text": "Analyze this image. Is it: 1) a banana leaf with banana wilt disease, 2) a healthy banana leaf, or 3) not a banana leaf at all? Respond with ONLY ONE of these words: 'WILT-AFFECTED', 'HEALTHY', or 'INVALID'."},
                    {
                        "inline_data": {
                            "mime_type": "image/jpeg",
                            "data": base64_image
                        }
                    }
                ]
            }]
        }
        
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload)
        )
        
        if response.status_code == 200:
            result = response.json()
            if not (result.get('candidates') and 
                    result['candidates'][0].get('content') and 
                    result['candidates'][0]['content'].get('parts') and
                    result['candidates'][0]['content']['parts'][0].get('text')):
                print(f"Gemini API response missing expected structure: {result}")
                return {
                    "is_banana_leaf": False, 
                    "label": "Error",
                    "explanation": "Error: Received malformed response from AI.",
                    "confidence": None
                }

            text_response = result['candidates'][0]['content']['parts'][0]['text'].strip().upper()
            
            label = "Uncertain"
            is_banana_leaf = True
            explanation = ""

            if "INVALID" in text_response:
                label = "Invalid"
                is_banana_leaf = False
                explanation = "The uploaded image does not appear to be a banana leaf."
            elif "WILT-AFFECTED" in text_response:
                label = "Wilt-Affected"
            elif "HEALTHY" in text_response:
                label = "Healthy"
            else: # Could be a safety block or unexpected response
                label = "Uncertain"
                explanation = "The AI analysis could not confidently determine the status or the content was blocked. Please try a clearer image or ensure it's appropriate."
                # Check for safety ratings if available and provide more specific feedback
                if result['candidates'][0].get('finishReason') == 'SAFETY':
                    explanation = "AI analysis blocked due to safety concerns. Please upload an appropriate image of a banana leaf."
                elif result['candidates'][0].get('finishReason') == 'OTHER':
                     explanation = "AI analysis resulted in an unexpected response. Please try again."


            # Simplified confidence
            confidence = 85.0 if label not in ["Invalid", "Uncertain", "Error"] else 60.0

            return {
                "is_banana_leaf": is_banana_leaf,
                "label": label,
                "explanation": explanation,
                "confidence": confidence
            }
        else:
            error_details = response.text
            print(f"Gemini API error: {response.status_code} - {error_details}")
            explanation = f"AI API Error ({response.status_code}). Please try again. Details: {error_details[:100]}"
            if "API key not valid" in error_details:
                explanation = "AI API Error: The API key is not valid. Please check your configuration."

            return {
                "is_banana_leaf": False, "label": "Error",
                "explanation": explanation,
                "confidence": None
            }
    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        return {"is_banana_leaf": False, "label": "Error", "explanation": "Network error connecting to AI service.", "confidence": None}
    except Exception as e:
        print(f"Error analyzing image with Gemini: {e}")
        return {"is_banana_leaf": False, "label": "Error", "explanation": "An unexpected error occurred during AI analysis.", "confidence": None}

def process_and_render_analysis(filepath, filename):
    analysis_result = analyze_image_with_gemini(filepath)
    
    if analysis_result is None or analysis_result.get("label") == "Error":
        flash(analysis_result.get("explanation", "An error occurred while analyzing the image."), "error")
        # For direct form submission, redirect back. For AJAX, this needs client-side handling.
        return redirect(url_for('dashboard')) 
            
    user_display_name = session.get('user_full_name', session.get('user_email', 'User'))
    
    context = {
        "filename": filename,
        "user_full_name": user_display_name,
        "is_banana_leaf": analysis_result["is_banana_leaf"],
        "label": analysis_result["label"],
        "confidence": analysis_result["confidence"],
        "explanation": analysis_result["explanation"],
        # "tips" are removed
    }

    if not analysis_result["is_banana_leaf"]:
        context["error_message"] = analysis_result["explanation"]
    
    return render_template('result.html', **context)


@app.route('/predict', methods=['POST'])
def predict():
    if not is_user_authenticated():
        flash("Please login to use the prediction service.", "warning")
        return redirect(url_for('login'))

    if 'image' not in request.files:
        flash('No file part. Please select an image.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    file = request.files['image']
    if file.filename == '':
        flash('No selected file. Please choose an image to upload.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        upload_folder_path = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder_path):
            try: os.makedirs(upload_folder_path)
            except OSError as e:
                flash(f"Could not create upload directory: {e}", "danger")
                return redirect(request.referrer or url_for('dashboard'))
        
        filepath = os.path.join(upload_folder_path, filename)
        
        try:
            file.save(filepath)
            return process_and_render_analysis(filepath, filename)
        except Exception as e:
            flash(f"An error occurred during the prediction process: {str(e)}", "error")
            print(f"UPLOAD PREDICTION PROCESS ERROR for {filename}: {e}")
            return redirect(request.referrer or url_for('dashboard'))

    flash('File could not be processed.', 'danger')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/predict_camera', methods=['POST'])
def predict_camera():
    if not is_user_authenticated():
        return {"error": "Authentication required", "redirect": url_for('login')}, 401

    data = request.get_json()
    if not data or 'image_data' not in data:
        return {"error": "No image data received"}, 400

    image_data_url = data['image_data']
    
    upload_folder_path = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder_path):
        try: os.makedirs(upload_folder_path)
        except OSError as e:
            return {"error": f"Could not create upload directory: {e}"}, 500
    
    try:
        # Ensure the data URL format is correct before splitting
        if not image_data_url.startswith('data:image/') or ',' not in image_data_url:
            return {"error": "Invalid image data URL format"}, 400

        header, encoded = image_data_url.split(",", 1)
        image_bytes = base64.b64decode(encoded)
        
        # Basic extension detection from mime type
        mime_type_part = header.split(':')[1].split(';')[0]
        extension = ".jpg" # Default
        if mime_type_part == "image/png": extension = ".png"
        elif mime_type_part == "image/jpeg": extension = ".jpg"
        # Add more if needed, or use a library for robust mime to extension mapping
            
        filename = f"capture_{uuid.uuid4().hex}{extension}"
        filepath = os.path.join(upload_folder_path, filename)
        
        with open(filepath, "wb") as f:
            f.write(image_bytes)
            
        # Use the refactored processing logic
        # Since process_and_render_analysis returns a Response object (rendered template or redirect)
        # and this route is called via AJAX, we need to handle its output for AJAX.
        # For simplicity, if it's a redirect due to an error, we'll signal JS to redirect.
        # If it's the result HTML, we send that.

        analysis_response = process_and_render_analysis(filepath, filename)
        
        if isinstance(analysis_response, str): # If it's HTML content
            return analysis_response, 200, {'Content-Type': 'text/html'}
        elif analysis_response.status_code == 302: # It's a redirect
             # This means an error occurred in process_and_render_analysis and it flashed/redirected.
             # We need to inform the client to reload or handle the flashed message.
             # For now, let's just send a generic error. A better way would be to have
             # process_and_render_analysis return JSON for AJAX calls.
            flash("An error occurred analyzing the captured image. Please check flashed messages on dashboard.", "error") # Flash for next page load
            return {"status": "error_redirect", "url": url_for('dashboard') }, 200 # Instruct JS to redirect
        else: # Should ideally not happen if process_and_render_analysis is consistent
            return analysis_response # Pass through whatever it returned


    except base64.binascii.Error as b64e:
        print(f"CAMERA PREDICTION BASE64 ERROR: {b64e}")
        return {"error": "Invalid base64 image data."}, 400
    except Exception as e:
        print(f"CAMERA PREDICTION PROCESS ERROR: {e}")
        return {"error": f"Error processing captured image: {str(e)}"}, 500


if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)