import os
import re
import json
import time
import requests
import urllib.parse
import yt_dlp
import cfscrape
from dotenv import load_dotenv
from pytubefix import Search
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, 
    create_access_token, 
    jwt_required, 
    get_jwt_identity
)
from models import db, User
import config
import stripe
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from fake_headers import Headers
from numerize_denumerize import denumerize
from flask_cors import CORS
from bs4 import BeautifulSoup
from models import db, User, SearchHistory


load_dotenv()
API_KEY = os.getenv("API_KEY")

app = Flask(__name__)
CORS(app)
app.config.from_object(config.config)
db.init_app(app)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = config.config.SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

stripe.api_key = config.config.STRIPE_SECRET_KEY

jwt = JWTManager(app)

@jwt.user_identity_loader
def user_identity_lookup(identity):
    """
    This receives whatever you pass as identity to create_access_token()
    Must return a serializable value (string, number)
    """
    return identity  # Just return it as-is since we already converted to string

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """
    Convert JWT identity (user id) to User object
    """
    identity = jwt_data["sub"]
    return User.query.get(identity)

# ---------------------- Utility: Credit Enforcement ----------------------
def require_credits(required):
    def decorator(fn):
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = User.query.get(get_jwt_identity())
            if user.plan is None:
                return jsonify({'error': 'No active subscription'}), 403
            if user.credits < required:
                return jsonify({'error': 'Not enough credits'}), 403
            user.credits -= required
            db.session.commit()
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

# ---------------------- Authentication ----------------------
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return {'error': 'Invalid credentials'}, 401
    
    access_token = create_access_token(identity=str(user.id))
    return {'token': access_token, 'user_id': user.id}

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(email=data['email']).first():
        return {'error': 'Email already exists'}, 400
    
    user = User(email=data['email'], password=generate_password_hash(data['password']))
    db.session.add(user)
    db.session.commit()
    
    access_token = create_access_token(identity=str(user.id))
    return {'token': access_token}

# ---------------------- Stripe Integration ----------------------
@app.route('/api/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.json
    
    price_map = {
        'basic': config.config.STRIPE_BASIC_PLAN_ID,
        'pro': config.config.STRIPE_PRO_PLAN_ID,
        'elite': config.config.STRIPE_ELITE_PLAN_ID
    }
    
    if data['plan'] not in price_map:
        return {'error': 'Invalid plan'}, 400

    try:
        session = stripe.checkout.Session.create(
            customer_email=user.email,
            payment_method_types=['card'],
            line_items=[{
                'price': price_map[data['plan']],
                'quantity': 1
            }],
            mode='subscription',
            success_url=f"{data['success_url']}?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=data['cancel_url'],
            metadata={
                'user_id': user.id,
                'plan': data['plan']
            }
        )
        return {'session_url': session.url}, 200
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/verify-payment', methods=['GET'])
@jwt_required()
def verify_payment():
    session_id = request.args.get('session_id')
    if not session_id:
        return {'error': 'Session ID is required'}, 400

    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status != 'paid':
            return {'error': 'Payment not completed'}, 400

        user = User.query.get(get_jwt_identity())
        subscription = stripe.Subscription.retrieve(session.subscription)
        
        plan = session.metadata.get('plan', 'basic')
        user.stripe_customer_id = session.customer
        user.stripe_subscription_id = session.subscription
        user.plan = plan
        user.credits = {'basic': 100, 'pro': 350, 'elite': 750}.get(plan, 0)
        db.session.commit()

        return {
            'success': True,
            'subscription': {
                'id': subscription.id,
                'status': subscription.status,
                'plan': user.plan,
                'current_period_end': subscription.current_period_end
            }
        }
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, config.config.STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        return {'error': 'Invalid payload'}, 400
    except stripe.error.SignatureVerificationError as e:
        return {'error': 'Invalid signature'}, 400

    if event['type'] == 'invoice.paid':
        data = event['data']['object']
        sub_id = data['subscription']
        user = User.query.filter_by(stripe_subscription_id=sub_id).first()
        if user:
            user.credits = {'basic': 100, 'pro': 350, 'elite': 750}.get(user.plan, 0)
            db.session.commit()

    if event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        user = User.query.filter_by(stripe_subscription_id=subscription.id).first()
        if user:
            user.plan = None
            user.stripe_subscription_id = None
            user.credits = 0
            db.session.commit()

    return {'success': True}, 200

# ---------------------- User Management ----------------------
@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user():
    user = User.query.get(get_jwt_identity())
    return {
        'email': user.email,
        'plan': user.plan,
        'credits': user.credits,
        'stripe_customer_id': user.stripe_customer_id
    }

@app.route('/api/pro-feature', methods=['GET'])
@require_credits(0)
def pro_feature():
    user = User.query.get(get_jwt_identity())
    if user.plan not in ['pro', 'elite']:
        return {'error': 'Upgrade to Pro or Elite to use this feature'}, 403
    return {'message': 'Access granted to Pro feature'}

# ---------------------- Shared Utility Functions ----------------------
def reverse_thumbnail_search(thumbnail_url):
    url = "https://google.serper.dev/lens"
    payload = json.dumps({"url": thumbnail_url})
    headers = {
        'X-API-KEY': API_KEY,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        return response.json().get('organic', [])
    except Exception as e:
        print(e)
        return []
    
def add_to_history(user_id, platform, metadata):
    platform_limits = {
        'youtube': config.config.MAX_YOUTUBE_HISTORY,
        'tiktok': config.config.MAX_TIKTOK_HISTORY,
        'reel': config.config.MAX_REEL_HISTORY,
    }
    max_items = platform_limits.get(platform, 15)

    history_items = SearchHistory.query.filter_by(user_id=user_id, platform=platform)\
        .order_by(SearchHistory.timestamp.desc()).all()

    if len(history_items) >= max_items:
        for old_item in history_items[max_items - 1:]:
            db.session.delete(old_item)

    db.session.add(SearchHistory(user_id=user_id, platform=platform, metadata=metadata))
    db.session.commit()

@app.route('/api/search-history', methods=['GET'])
@jwt_required()
def api_get_all_search_history():
    user_id = get_jwt_identity()

    # Platform-specific limits
    limits = {
        'youtube': config.config.MAX_YOUTUBE_HISTORY,
        'tiktok': config.config.MAX_TIKTOK_HISTORY,
        'reel': config.config.MAX_REEL_HISTORY
    }

    # Initialize all categories
    categorized_history = {
        'youtube': [],
        'tiktok': [],
        'instagram': [],
        'other': []
    }

    # Get all history for user
    all_entries = SearchHistory.query.filter_by(user_id=user_id).order_by(SearchHistory.timestamp.desc()).all()

    # Temporary counters
    counters = {
        'youtube': 0,
        'tiktok': 0,
        'reel': 0
    }

    for entry in all_entries:
        platform = entry.platform
        history_item = {
            'timestamp': entry.timestamp.isoformat(),
            'metadata': entry.metadata
        }

        if platform in ['youtube', 'tiktok', 'reel']:
            if counters[platform] < limits[platform]:
                if platform == 'reel':
                    categorized_history['instagram'].append(history_item)
                else:
                    categorized_history[platform].append(history_item)
                counters[platform] += 1
        else:
            categorized_history['other'].append(history_item)

    return jsonify(categorized_history)



# ---------------------- Instagram Endpoints ----------------------
def third_party_html_to_dict(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    # Extract profile information
    profile_section = soup.find('section', {'id': 'download-box-profile'})
    profile_data = {
        'username': profile_section.find('p', class_='h4').get_text(strip=True) if profile_section else None,
        'full_name': profile_section.find('p', class_='text-muted').get_text(strip=True) if profile_section else None
    }
    # Extract first post data
    first_post = soup.find('div', {'class': 'col-md-4'})
    post_data = {
        'thumbnail_url': first_post.find('video')['poster'] if first_post and first_post.find('video') else None,
        'media_url': first_post.find('source')['src'] if first_post and first_post.find('source') else None,
        'caption': first_post.find('p', {'class': 'text-sm'}).get_text(strip=True) if first_post and first_post.find('p', {'class': 'text-sm'}) else None,
        'likes': first_post.find('i', {'class': 'far fa-heart'}).find_parent('small').get_text(strip=True) if first_post and first_post.find('i', {'class': 'far fa-heart'}) else None,
        'comments': first_post.find('i', {'class': 'far fa-comment'}).find_parent('small').get_text(strip=True) if first_post and first_post.find('i', {'class': 'far fa-comment'}) else None
    } if first_post else None
    username = profile_data['username']
    full_name = profile_data['full_name']
    thumbnail_url = post_data['thumbnail_url']
    media_url = post_data['media_url']
    caption = post_data['caption']
    likes = post_data['likes']
    comments = post_data['comments']
    return {
        'username': username,
        'full_name': full_name,
        'thumbnail_url': thumbnail_url,
        'video_url': media_url,
        'description': caption,
        'likes_count': denumerize.denumerize(likes),
        'comments_count': denumerize.denumerize(comments),
    }

def get_reel_metadata(reel_url):
  r = requests.get('https://igram.website/content.php', params={'url': reel_url})
  data = third_party_html_to_dict(r.json()['html'])
  return data

def filter_instagram_results(results):
    return [i for i in results if i['source'].lower() == 'instagram' and 'reel/' in i['link']]

def filter_by_likes_and_comments(data, likes_range=None, comments_range=None):
    filtered_data = []
    for item in data:
        likes_condition = True
        if likes_range:
            if item['likes_count'] == None:
                 item['likes_count'] = 0
            likes_condition = int(likes_range[0]) <= int(item['likes_count']) <= int(likes_range[1])
        comments_condition = True
        if comments_range:
            if item['comments_count'] == None:
                 item['comments_count'] = 0
            comments_condition = int(comments_range[0]) <= int(item['comments_count']) <= int(comments_range[1])
        if likes_condition and comments_condition:
            filtered_data.append(item)
    return filtered_data

def search_reels(query):
    url = "https://google.serper.dev/search"
    headers = {
        "X-API-KEY": API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "q": f"{query} site:instagram.com/reel",
        "gl": "us",
        "hl": "en"
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        results = response.json().get("organic", [])
        clean_results = []
        for item in results:
            link = item.get('link')
            if 'instagram.com/reel/' not in link:
                continue
            clean_results.append({
                'url': link,
                'description': item.get('title')
            })
        return clean_results
    except Exception as e:
        print("Error in Serper search:", e)
        return []

# Tested
@app.route('/get-reel-metadata/', methods=['POST'])
@require_credits(1)
def api_get_reel_metadata():
    data = get_reel_metadata(request.get_json()['url'])
    add_to_history(get_jwt_identity(), 'reel', data)
    return jsonify(data)


@app.route('/instagram-reverse-thumbnail-search/', methods=['POST'])
@require_credits(5)
def api_instagram_reverse_thumbnail_search():
    results = reverse_thumbnail_search(request.get_json()['thumbnail_url'])
    toret = filter_instagram_results(results)
    return jsonify(toret)

# Tested
@app.route('/filter-by-likes-and-comments/', methods=['POST'])
@require_credits(0)
def api_filter_by_likes_and_comments():
    data = request.get_json()
    try: likes_range = data['likes_range'].split('-')
    except: likes_range = [0, 99999999]
    try: comments_range = data['comments_range'].split('-')
    except: comments_range = [0, 99999999]
    return jsonify(filter_by_likes_and_comments(data['videos'], likes_range, comments_range))

# Tested
@app.route('/search-reels/', methods=['POST'])
@require_credits(0)
def api_search_reels():
    return jsonify(search_reels(request.get_json()['query']))

# ---------------------- TikTok Endpoints ----------------------
def get_tiktok_metadata(url):
    try:
        data = requests.get("https://www.tiktok.com/oembed", params={'url': url}).json()
        return {
            'author': data['author_unique_id'],
            'author_name': data['author_name'],
            'author_url': data['author_url'],
            'title': data['title'],
            'thumbnail_url': data['thumbnail_url'].replace('\n', ''),
        }
    except:
        return {"error": "Invalid TikTok link or response failed."}

def download_tiktok(url):
    patterns = [
        r'tiktok\.com/@[^/]+/video/(\d+)',
        r'tiktok\.com/v/(\d+)',
        r'tiktok\.com\/.*video_id=(\d+)',
        r'/video/(\d+)',
        r'(\d{10,20})'
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            tiktok_id = match.group(1)
            break
    else:
        return None
    direct_url = 'https://tikcdn.io/ssstik/' + tiktok_id
    if requests.head(direct_url).status_code == 200:
        return direct_url
    cl = cfscrape.create_scraper()
    tt_key = re.search(r"s_tt\s*=\s*'([^']+)'", cl.get('https://ssstik.io/').text).group(1)
    resp = cl.post('https://ssstik.io/abc?url=dl', data={'id': url, 'locale': 'en', 'tt': tt_key})
    return re.search(r'<a\s+href="([^"]+)"[^>]+download_link[^>]+>', resp.text).group(1)

# Tested
@app.route('/download-tiktok/', methods=['POST'])
@require_credits(0)
def api_download_tiktok():
    return jsonify({'download_url': download_tiktok(request.get_json()['url'])})

# Tested
@app.route('/get-tiktok-metadata/', methods=['POST'])
@require_credits(1)
def api_get_tiktok_metadata():
    meta = get_tiktok_metadata(request.get_json()['url'])
    if "error" not in meta:
        add_to_history(get_jwt_identity(), 'tiktok', meta)
        return jsonify(meta), 200
    else:
        return jsonify(meta), 400


# Tested
@app.route('/tiktok-reverse-thumbnail-search/', methods=['POST'])
@require_credits(5)
def api_tiktok_reverse_thumbnail_search():
    url = request.get_json()['thumbnail_url'].replace('\n', '')
    results = reverse_thumbnail_search(url)
    toret = []
    for i in results:
        if 'tiktok' in i['source'].lower() and '/video' in i['link']:
            toret.append(i)
    try:
        return jsonify(toret), 200
    except:
        return jsonify({"error": "Something went wrong"}), 400

# ---------------------- YouTube Endpoints ----------------------
def extract_video_id(url):
    match = re.search(r'(?:v=|\/)([a-zA-Z0-9_-]{11})(?:&|$)', url)
    return match.group(1) if match else url if len(url) == 11 else None


# Not being used but could use it in case v2 fails
def get_video_metadata(video):
    video_id = extract_video_id(video)
    params = {
        "key": "foo1",
        "quotaUser": "WHQssHmB6JixluhJzlJjmNzmgBFelxHiKPUofnrx",
        "part": "snippet,statistics,contentDetails,status",
        "id": video_id
    }
    try:
        headers = {
            "Accept": "application/json",
            "Origin": "https://mattw.io",
            "Referer": "https://mattw.io/",
            "User-Agent": "Mozilla/5.0"
        }
        r = requests.get("https://ytapi.apps.mattw.io/v3/videos", params=params, headers=headers).json()
        if r.get("items"):
            data = r["items"][0]
            s, st = data["snippet"], data["statistics"]
            return {
                'title': s["title"],
                'description': s["description"],
                'url': f"https://www.youtube.com/watch?v={video_id}",
                'thumbnail_url': s["thumbnails"].get("maxres", {}).get("url", ""),
                'views': st.get("viewCount", 0),
                'likes': st.get("likeCount", 0),
                'comments': st.get("commentCount", 0),
                'upload_date': s.get("publishedAt", "").split("T")[0],
                'author': s.get("channelTitle", "N/A")
            }
    except Exception as e:
        print(e)
    return None

def fetch_file_url(client, url, max_retries, delay):
    """Try fetching the direct file URL, retrying if it's not ready yet."""
    for attempt in range(max_retries):
        try:
            resp = client.post('https://ytdown.io/proxy.php', data={'url': url})
            data = resp.json()
            file_url = data.get('api', {}).get('fileUrl')

            if file_url != 'In Processing...':  # Success
                return file_url
        except Exception:
            pass  # Ignore and retry

        time.sleep(delay)  # Wait before retrying

    return None  # Failed after retries

def get_video_info_basic(video_url):
    """Fetch video metadata without waiting for download URLs."""
    req_url = 'https://ytdown.io/proxy.php'
    headers = Headers().generate()
    client = requests.session()
    client.headers = headers
    payload = {'url': video_url}

    try:
        response = client.post(req_url, data=payload).json()['api']
    except Exception:
        return None  # API failure

    # Channel Info
    channel_data = {
        'name': response['userInfo']['name'],
        'username': response['userInfo']['username'],
        'bio': response['userInfo']['userBio'],
        'media_count': response['mediaStats']['mediaCount'],
        'followers_count': response['mediaStats']['followersCount'],
    }

    # Video Info (no formats yet)
    video_data = {
        'views': denumerize.denumerize(str(response['mediaStats']['viewsCount'])),
        'comments': denumerize.denumerize(str(response['mediaStats']['commentsCount'])),
        'title': response['title'],
        'description': response['description'],
        'preview_url': response['previewUrl'],
        'thumbnail_url': response['imagePreviewUrl']
    }

    # Attempt to enrich video data
    try:
        additional_data = get_video_metadata(video_url)
        video_data['likes'] = denumerize.denumerize(str(additional_data.get('likes', 0)))
        video_data['author'] = additional_data.get('author', '')
        video_data['upload_data'] = additional_data.get('upload_date', '')
    except:
        video_data['likes'] = 0
        video_data['author'] = ''
        video_data['upload_data'] = ''

    return video_data

def get_video_download_formats(video_url, max_retries=2, delay=30):
    """Fetch only the available video download formats."""
    req_url = 'https://ytdown.io/proxy.php'
    headers = Headers().generate()
    client = requests.session()
    client.headers = headers
    payload = {'url': video_url}

    try:
        response = client.post(req_url, data=payload).json()['api']
    except Exception:
        return None

    raw_formats = response['mediaItems']
    url_list = [item['mediaUrl'] for item in raw_formats if item['type'] == 'Video']

    # Parallel fetching with retry potential
    with ThreadPoolExecutor(max_workers=5) as executor:
        file_urls = list(executor.map(lambda url: fetch_file_url(client, url, max_retries, delay), url_list))

    available_formats = []
    for element, file_url in zip(raw_formats, file_urls):
        if file_url:
            available_formats.append({
                'resolution': element['mediaRes'],
                'size': element['mediaFileSize'],
                'download_url': file_url
            })

    return available_formats

# Tested
@app.route('/get-video-metadata/', methods=['POST'])
@require_credits(1)
def api_get_video_metadata():
    url = request.get_json()['url']
    data = get_video_info_basic(url)
    add_to_history(get_jwt_identity(), 'youtube', data)
    return jsonify(data)


# Tested
@app.route('/download-youtube-video/', methods=['POST'])
@require_credits(0)
def api_get_video_download_formats():
    url = request.get_json()['url']
    max_retries = request.get_json().get('max_retries', 2)
    delay = request.get_json().get('delay', 30)
    return jsonify(get_video_download_formats(url, max_retries, delay))

# Tested
@app.route('/youtube-reverse-thumbnail-search/', methods=['POST'])
@require_credits(5)
def api_youtube_reverse_thumbnail_search():
    results = reverse_thumbnail_search(request.get_json()['thumbnail_url'])
    toret = [r for r in results if r['source'] == 'YouTube']
    return jsonify(toret)

# Tested
@app.route('/get-top-search-results/', methods=['POST'])
@require_credits(0)
def api_get_top_search_results():
    return jsonify({'results': [r.watch_url for r in Search(request.get_json()['title']).results]})

# Tested
@app.route('/generate-similar-titles/', methods=['POST'])
@require_credits(0)
def api_generate_similar_titles():
    t = request.get_json()['title']
    url = f"https://rephrasesrv.gingersoftware.com/Rephrase/secured/rephrase?apiKey=GingerWebsite&clientVersion=2.0&lang=en&s={urllib.parse.quote(t)}&size=8"
    r = requests.get(url).json()
    return jsonify({'generated_titles': [f"{i+1}. {s['Sentence']}" for i, s in enumerate(r.get('Sentences', []))]})

# Tested
@app.route('/compute-similarity/', methods=['POST'])
@require_credits(0)
def api_compute_similarity():
    d = request.get_json()
    b = {'text_1': f"{d['video1'].get('title', '')} {d['video1']['description']}", 'text_2': f"{d['video2'].get('title', '')} {d['video2']['description']}"}
    r = requests.post('https://api.api-ninjas.com/v1/textsimilarity',
                      headers={'X-Api-Key': 'iA1uG7UEmJtOuvU1MrS9Kw==bLdVLc81sdAwwpRd'}, json=b).json()
    return jsonify({'similarity': round(r['similarity'] * 100, 2)})

# ---------------------- Run App ----------------------
if __name__ == '__main__':
    #with app.app_context():
    #    db.create_all()

    with app.app_context():
        email = "dhiahanafi@example.com"
        password = "dhiahanafi"
        hashed_password = generate_password_hash(password)
        plan = "pro"  # or 'basic', 'elite'
        credits = 999

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print("User already exists.")
        else:
            user = User(email=email, password=hashed_password, plan=plan, credits=credits)
            db.session.add(user)
            db.session.commit()
            print(f"Created test user: {email} with plan: {plan} and credits: {credits}")
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)


