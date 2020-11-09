import secrets
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message
import socket

from cs50 import SQL
import os
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for, abort
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["MAIL_SERVER"] = 'smtp.googlemail.com'
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get('EMAIL_USER')
app.config["MAIL_PASSWORD"] = os.environ.get('EMAIL_PASS')
mail = Mail(app)
Session(app)


'''Email and Password reset token'''
def get_reset_token(someone, expires_sec=1800):

    s = Serializer(app.config['SECRET_KEY'], expires_sec)
    return s.dumps({'user_id': someone}).decode('utf-8')

'''Verifying token'''
@staticmethod
def verify_reset_token(token):
    s = Serializer(app.config['SECERT_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        return None
    return db.execute("SELECT * FROM database WHERE id = ?", user_id)



# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")



"""For Badges"""
def badges():
    # Friend request details
    fr_rq_details = db.execute("SELECT * FROM ? WHERE declined = 0 ORDER BY time_fr DESC", f'{session["username"]} friends')
    badge = len(fr_rq_details)
    if badge == 0:
        badge = ""

    friend_rqs = {"rqs": fr_rq_details, "badges": badge}
    return friend_rqs

"""For unread messages"""
def unopened(friend_id):

    unread_messages = db.execute("SELECT * FROM ? WHERE friend = ? AND read = 0 AND recieved = 1 AND deleted = 0", f"{session['username']} messages", friend_id)
    no_unread = len(unread_messages)
    if no_unread == 0:
        no_unread = ""
    return {"unread_messages": unread_messages, "no_unread": no_unread}


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username!", "danger")
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):

            flash("Must provide password!", "danger")
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM database WHERE username = :username", username = request.form.get("username").capitalize())
        # Query database for email
        if len(rows) != 1:
            rows = db.execute("SELECT * FROM database WHERE email =:email", email = request.form.get("username").lower())

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            flash("Invalid username and/or password!", "danger")
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]
        session["email"] = rows[0]["email"]


        flash("Logged in!", "success")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # if method is "GET", just show the page
    if request.method == "GET":
        return render_template("register.html")

    # else (method is "POST"), submit details typed in input fields
    else:

        # get details from page
        username = request.form.get("username").capitalize()
        email = request.form.get("email").lower()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            flash("Must provide username!", "danger")
            return apology("You must input a username")

        if not email:
            flash("Must provide an email!", "danger")
            return apology("You must input an email")

        # Ensure username and emial has not already been taken
        users = db.execute("SELECT * FROM database WHERE username = ?", username)
        for line in users:
            if line["username"].lower() == username.lower():
                flash("This username is already taken.", "danger")
                return apology("This username is already taken")

            if line["email"].lower() == email.lower():
                flash("This email is already taken.", "danger")
                return apology("This email is already taken")

        # Ensure password was submitted
        if not password:
            flash("Must provide password!", "danger")
            return apology("You must provide a password")

        # Ensure confirmation password was submitted
        if not confirmation:
            flash("Please confirm password!", "danger")
            return apology("Please confirm password")

        # Ensure password and confirmation are the same
        if not password == confirmation:
            flash("Passwords do not match!", "danger")
            return apology("Passwords do not match")

        # Register user
        db.execute("INSERT INTO database (username, email, password) VALUES (?, ?, ?)", username, email, generate_password_hash(password))

        # Create table for user's friends and friend requests. When accepted, the accepted coloumn will get updated to 1 else the friend will remain 0
        db.execute("CREATE TABLE IF NOT EXISTS ? (id INTEGER FORIEGN KEY REFERENCES database(id), username TEXT, accepted INTEGER DEFAULT 0 NOT NULL, time_fr NUMERIC, time_accepted NUMERIC DEFAULT 0 NOT NULL, declined INTEGER DEFAULT 0)", f"{username} friends")

        # Create table for user's messages
        db.execute("CREATE TABLE IF NOT EXISTS ? (id INTEGER PRIMARY KEY, message TEXT NOT NULL, friend INTEGER FORIEGN KEY REFERENCES database(id), sent INTEGER DEFAULT NULL, recieved INTEGER DEFAULT NULL, time NUMERIC DEFAULT 0, read INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0)", f"{username} messages")

        flash(f'Account created for {username}.', 'success')
        return redirect("/login")


@app.route("/")
@login_required
def index():
    """Show friend list of user and newsfeed for user"""
    posts = db.execute("SELECT posts.id, title, date, content, author, database.username FROM posts JOIN database ON posts.author = database.id ORDER BY date DESC")
    friends = db.execute("SELECT *, database.username AS current_username FROM ? JOIN database ON ?.id = database.id WHERE accepted = 1", f'{session["username"]} friends', f'{session["username"]} friends')

    unread = {}

    for friend in friends:
        if friend["id"] not in unread:
            unread[friend['id']] = unopened(friend['id'])["no_unread"]


    return render_template("index.html", friends=friends, posts=posts, badges=badges(), unread=unread)



# Function for saving profie picture
def save_picture(form_picture):
    # Randomize filename to be sure filename doesn't already exist
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)

    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    form_picture.save(picture_path)
    return picture_fn




@app.route("/account/<someone>", methods=["GET", "POST"])
@login_required
def account(someone):

    if someone == session["username"]:
        """Show user account info"""
        # If get method is GET
        if request.method == "GET":

            details = db.execute("SELECT * FROM database WHERE id = ?", session["user_id"])
            posts = db.execute("SELECT * FROM posts WHERE author = ? ORDER BY DATE DESC", session["user_id"])
            total = len(posts)

            if details[0]["image"] == "default.jpg":
                details[0]["image"] = url_for("static", filename='profile_pics/'+'default.jpg')


            return render_template("user_account.html", badges=badges(), details=details, posts=posts, total=total)

        # If method is POST
        else:
            username = request.form.get("username")
            email = request.form.get("email")
            pic = request.form.get("pic")
            bio = request.form.get("bio")

                # Ensure username was submitted
            if not username:
                flash("Must provide username!", "danger")
                return apology("You must input a username")

            if not email:
                flash("Must provide an email!", "danger")
                return apology("You must input an email")


            users = db.execute("SELECT * FROM database WHERE username = ?", username)

            # If email or username was updated, run checks with database
            if (username != session["username"]) or (email != session["email"]):
                for line in users:
                    if line["username"].lower() == username.lower():
                        flash("This username is already taken.", "danger")
                        return apology("This username is already taken")

                    if line["email"].lower() == email.lower():
                        flash("This email is already taken.", "danger")
                        return apology("This email is already taken")

            # I found no shorter way to do this, please bear with me
            if username:
                username = username.capitalize()
                if username != session["username"]:
                    # Rename user's friends and messages table
                    db.execute("ALTER TABLE ? RENAME TO ?", f'{session["username"]} friends', f'{username} friends')

                    db.execute("ALTER TABLE ? RENAME TO ?", f'{session["username"]} messages', f'{username} messages')

                db.execute("UPDATE database SET username = ? WHERE username = ?", username, session["username"])
                session["username"] = username

            if email:
                email = email.lower()
                db.execute("UPDATE database SET email = ? WHERE username = ?", email, session["username"])
                session["email"] = email

            # If profile picture was updated
            if pic:
                root, ext = os.path.splitext(pic.filename)
                # If file is not an image
                if ext not in [".jpeg", ".jpg", ".png"]:
                    flash("Upload only files of .jpeg, .jpg and ,png externsions.", "danger")
                    return apology("Invalid file type.")

                picture_file = save_picture(pic)
                db.execute("UPADTE database SET image = ? WHERE id = ?", picture_file, session["user_id"])

            if bio:
                db.execute("UPDATE database SET bio = ? WHERE username = ?", bio, session["username"])


            flash("Account info upadted", "success")
            return redirect(f"/account/{session['username']}")

    else:

        details = db.execute("SELECT * FROM database WHERE username = ?", someone.capitalize())
        posts = db.execute("SELECT * FROM posts JOIN database ON posts.author = database.id WHERE username = ? ORDER BY DATE DESC", someone)
        total = len(posts)

        if not details:
            flash("No such user with the url you provided.", "danger")
            return apology("No such user with the url you provided.")

        if details[0]["image"] == "default.jpg":
                details[0]["image"] = url_for("static", filename='profile_pics/'+'default.jpg')

        # For accept/decline links at the bottom of the page
        check = db.execute("SELECT * FROM ? WHERE username = ?", f'{session["username"]} friends', someone)

        return render_template("account.html", details=details, badges=badges(), check=check, posts=posts, total=total, someone=someone)



@app.route("/add_friend", methods=["GET", "POST"])
@login_required
def add():

    # If method = GET
    if request.method == "GET":

        return render_template("add.html", badges=badges())

    # Method is Post
    else:
        username = request.form.get("username").capitalize()

        # If username was not typed in
        if not username:
            flash("Please input a username!", "danger")
            return apology("Please input a username")

        # Check for new friend in general database
        rows = db.execute("SELECT * FROM database WHERE username = (?)", username)


        # If friend username was not found on YensoGram
        if len(rows) != 1:

            flash("Username is not on Yensogram. Please check username again.", "danger")
            return apology("Username is not on Yensogram. Please check username again.")

        # If friend username was found on YensoGram
        for row in rows:

            # If user tried to add himself as a friend
            if row["username"].lower() == session["username"].lower():
                flash("You can't add yourself as a friend.", "danger")
                return apology("You can't add yourself as a friend.")

        # Check if user already has the username as a friend
        check = db.execute("SELECT * FROM ? WHERE username = (?)", f'{session["username"]} friends', rows[0]["username"])
        if len(check) == 1:
            flash("You already have this user as a friend.", "danger")
            return apology("You already have this user as a friend.")

        # Send request to friend
        #db.execute("INSERT INTO ? (username, time) VALUES (?, datetime('now'))", f'{rows[0]["username"]} friend requests', session["username"])

        # Insert user into friend's friend list but unaccepted
        db.execute("INSERT INTO ? (id, username, time_fr) VALUES ((SELECT id FROM database WHERE username = ?), ?, datetime('now', 'localtime'))", f'{rows[0]["username"]} friends', session["username"], session["username"])

        # Insert friend into user's freind list but unaccepted
        db.execute("INSERT INTO ? (id, username, time_fr, declined) VALUES ((SELECT id FROM database WHERE username = ?), ?, datetime('now', 'localtime'), NULL)", f'{session["username"]} friends', rows[0]["username"], rows[0]["username"])

        flash("Request sent.", "success")
        return redirect("/add_friend")


# Route for user's friend requests
@app.route("/friend_requests")
@login_required
def friend_request():
    # Show friend requests
    return render_template("friend_rqs.html", friend_rqs=badges(), badges=badges())



# Route for accepting friend requests
@app.route("/friend_requests_accept/<friend>")
@login_required
def friend_request_accept(friend):

    # Update user's friend list and add friend by setting accepted to 1
    db.execute("UPDATE ? SET accepted = 1, time_accepted = datetime('now'), declined = NULL WHERE username = ?", f'{session["username"]} friends', friend.capitalize())

    # Update friends's friend list and add user by setting accepted to 1
    db.execute("UPDATE ? SET accepted = 1, time_accepted = datetime('now') WHERE username = ?", f'{friend} friends', session["username"].capitalize())


    return redirect("/friend_requests")



# Route for declining friend requests
@app.route("/friend_requests_decline/<friend>")
@login_required
def friend_request_decline(friend):

    # Update user's friend list and "delete" friend by setting declined to 1
    db.execute("UPDATE ? SET declined = 1 WHERE username = ?", f'{session["username"]} friends', friend.capitalize())

    return redirect("/friend_requests")



# This route shows messages between user and friend.
@app.route("/<some_user_id>/<some_username>", methods=["GET", "POST"])
# You have to be looged in to see your messages with such user
@login_required
def message(some_user_id, some_username):

    if request.method == "GET":

        # Check if the searched person(some_user) has an account on YG.
        rows = db.execute("SELECT * FROM database WHERE id = ?", some_user_id)

        # If searched person(some_user) is not on YG:
        if len(rows) != 1:
            return render_template('info.html', user=session["username"], badges=badges(), info="There is no such user on YensoGram with the URL you provided.")

        # The searched person is on YG
        else:

            # Check if the person is friends with the user
            lines = db.execute("SELECT * FROM ? WHERE id = ?", f'{session["username"]} friends', some_user_id)

            # If searched person is not friends with the user
            if len(lines) != 1:
                return render_template("info.html", user=session["username"], badges=badges, info=f"You are not friends with this user. Add {some_username} as a friend to see your messages.")

            # Get read messages between them
            read_messages = db.execute("SELECT * FROM ? WHERE friend = ? AND deleted = 0 AND read = 1", f"{session['username']} messages", some_user_id)

            # Get number of unread messages between them
            unread = unopened(some_user_id)

            # Set all messages between user and friend to read
            db.execute("UPDATE ? SET read = 1 WHERE friend = ?", f"{session['username']} messages", some_user_id)


            # Searched person is friends with user, so show  their messages together
            return render_template("messages.html", read_messages=read_messages, badges=badges(), some_user=rows[0], unread=unread)

    # Request method is post
    else:

        message = request.form.get("message")

        if not message:
            flash("Your message is empty.", "warning")
            return apology("Your message is empty.")

        # Insert message into user's messages
        db.execute("INSERT INTO ? (message, friend, sent, recieved, read, time) VALUES (?, ?, 1, 0, 1, datetime('now', 'localtime'))", f"{session['username']} messages", message, some_user_id)

        # Insert message into friends's messages
        db.execute("INSERT INTO ? (message, friend, sent, recieved, time) VALUES (?, ?, 0, 1, datetime('now', 'localtime'))", f"{some_username} messages", message, session["user_id"])

        return redirect(f"/{some_user_id}/{some_username}")



# Route for deleting messages for only user
@app.route("/delete_me/<int:friend>/<int:ID>")
@login_required
def delete_me(friend, ID):

    # Delete from user's messages
    db.execute("UPDATE ? SET deleted = 1 WHERE id = ? AND friend = ?", f"{session['username']} messages", ID, friend)

    # To know know the friend's username so as to redirect to correct route
    friend = db.execute("SELECT *, ?.friend AS person FROM ? JOIN database ON ?.friend = database.id WHERE ?.id = ?", f"{session['username']} messages", f"{session['username']} messages", f"{session['username']} messages", f"{session['username']} messages", ID)
    return redirect(f"/{friend[0]['person']}/{friend[0]['username']}")


# Route for deleting messages for both user and friend
@app.route("/delete_everyone/<int:friend>/<int:ID>")
@login_required
def delete_everyone(friend, ID):

    # Delete from user's messages
    db.execute("UPDATE ? SET deleted = 1 WHERE id = ? AND friend = ?", f"{session['username']} messages", ID, friend)

    # To get the name of friend's table of friends
    reciepient = db.execute("SELECT *, database.id AS person FROM ? JOIN database ON ?.friend = database.id",f"{session['username']} messages", f"{session['username']} messages")

    # To get time of message so as to make deletion specific for that particular message
    time = db.execute("SELECT time FROM ? WHERE id = ?", f"{session['username']} messages", ID)

    # Delete from friend's messages
    db.execute("UPDATE ? SET deleted = 1 WHERE message = (SELECT message from ? WHERE id = ?) AND friend = ? AND time = ?", f"{reciepient[0]['username']} messages", f"{session['username']} messages", ID, session["user_id"], time[0]["time"])

    return redirect(f"/{reciepient[0]['person']}/{reciepient[0]['username']}")



# Route for creating a new post
@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():

    if request.method == "GET":
        post = ""
        return render_template("create_post.html", badges=badges(), legend="New Post", post=post)

    else:
        title = request.form.get("title")
        content = request.form.get("content")

        if not title:
            flash("Your post must have a title!", "danger")
            return apology("Your post must have a title!")

        if not content:
            flash("Your post must have a content!", "danger")
            return apology("Your post must have a content!")

        # Insert post into posts table
        db.execute("INSERT INTO posts (title, date, content, author) VALUES (?, datetime('now'), ?, ?)", title, content, session["user_id"])

        flash("Your post has been created", "success")
        return redirect("/")


# Route for each individual post
@app.route("/post/<int:post_id>")
@login_required
def post(post_id):

    post = db.execute("SELECT posts.id, title, date, content, author, database.username FROM posts JOIN database ON posts.author = database.id WHERE posts.id = ?", post_id)
    if not post:
        return apology("No such post", 404)
    return render_template("post.html", post=post, badges=badges())


# Route for updating a post
@app.route("/post/<int:post_id>/update", methods=["GET", "POST"])
@login_required
def update_post(post_id):

    if request.method == "GET":

        post = db.execute("SELECT * FROM posts WHERE id = ?", post_id)
        if post[0]["author"] != session["user_id"]:
            abort(403)

        return render_template("create_post.html", badges=badges(), legend="Update Post", post=post)

    else:
        title = request.form.get("title")
        content = request.form.get("content")

        if not content:
            flash("Your post must have a content!", "danger")
            return apology("Your post must have a content!")

        # Insert post into posts table
        db.execute("UPDATE posts SET title = ?, content = ? WHERE id = ?", title, content, post_id)

        flash("Your post has been updated!", "success")
        return redirect(f"/post/{post_id}")


# Route for deletingting a post
@app.route("/post/<int:post_id>/delete")
@login_required
def delete_post(post_id):

    post = db.execute("SELECT * FROM posts WHERE id = ?",post_id)

    if post[0]["author"] != session["user_id"]:
        abort(403)

    # Delete post from database
    db.execute("DELETE FROM posts WHERE id = ?", post_id)
    flash("Your post has been deleted!", "success")
    return redirect("/")

# Function for email message
def send_reset_email(user):
    token = get_reset_token(user['id'])
    msg = Message("Password Reset Request", sender="noreply@demo.com", recipients=[user["email"]])
    msg.body = f'''Visit the following link to reset your password:

{url_for('reset_token', token=token, _external=True)}

If you did not make this request, please ignore.'''
    mail.send(msg)


# Route for requesting reset password
@app.route("/reset_password", methods=["GET", "POST"])
def reset_request():

    if request.method == "GET":
        # log user out
        session.clear()
        return render_template("reset_request.html")

    else:
        email = request.form.get("email").lower()

        if not email:
            flash("Must provide an email!", "danger")
            return apology("You must input an email")

        # Ensure username and emial has not already been taken
        users = db.execute("SELECT * FROM database WHERE email = ?", email)

        if not users:
            flash("There is no account with this email. Please sign up first.", "danger")
            return apology("There is no account with this email. Please sign up first.")

        for line in users:
            send_reset_email(line)
        flash("An email has been sent to reset your password.", "info")
        return redirect("/login")




# Route for reseting password
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_token(token):

    if request.method == "GET":
        # log user out
        session.clear()

        user = verify_reset_token(token)
        if not user:
            flash("This is an invalid or expired token.", "warning")
            return redirect("/reset_password")

        return render_template("reset_token.html")

    else:
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure password was submitted
        if not password:
            flash("Must provide password!", "danger")
            return apology("You must provide a password")

        # Ensure confirmation password was submitted
        if not confirmation:
            flash("Please confirm password!", "danger")
            return apology("Please confirm password")

        # Ensure password and confirmation are the same
        if not password == confirmation:
            flash("PasswordS do not match!", "danger")
            return apology("Passwords do not match")

        # Register user
        db.execute("UPDATE database SET password = ? WHERE id = ?", generate_password_hash(password), user.id)
        return redirect("/login")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
        flash(f"{e.name}!", "danger")
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)








