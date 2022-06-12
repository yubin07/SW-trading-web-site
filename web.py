from itertools import product
from nturl2path import pathname2url
from flask import Flask, flash, redirect, render_template, send_from_directory, request, session, url_for,escape
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
#from werkzeug.utils import secure_filename
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_migrate import Migrate
from functools import wraps
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
UPLOAD_FOLDER = './static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# database initiation and creation
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'anything'
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


followers = db.Table('followers',
    db.Column('follower_id', db.String, db.ForeignKey('user.username')),
    db.Column('followed_id', db.String, db.ForeignKey('user.username'))
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True, unique=True, autoincrement = True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == username),
        secondaryjoin=(followers.c.followed_id == username),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    
    def __init__(self, fullname, username, password):
        self.fullname = fullname
        self.username = username
        self.password = password 
    def follow(self, user):
        if not self.is_following(user): # follow 상태가 아닌지 확인
            self.followed.append(user)  # user가 self에 follow
    # user가 self에 되어있는 follow 제거
    def unfollow(self, user):
        if self.is_following(user):     # follow 상태인지 확인
            self.followed.remove(user)  # user가 self에 follow
    # 두 사용자 간의 링크가 존재하는지 확인
    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.username).count() > 0

#db product table
class Products(db.Model):
    id=db.Column(db.Integer,primary_key=True,unique=True,autoincrement=True)
    pname=db.Column(db.String(30),nullable=False)
    pdescript=db.Column(db.String(100),nullable=False)
    pkeyword=db.Column(db.String(30),nullable=False)
    pstate=db.Column(db.String(10),nullable=False) #sell/sold out
    puser=db.Column(db.String(10)) #uploader's info
    pimag=db.Column(db.String(100))
    #if we need image,put here
    def __init__(self,pname,pdescript,pkeyword,pstate,puser,pimag):
        #self.id=id
        self.pname=pname
        self.pdescript=pdescript
        self.pkeyword=pkeyword
        self.pstate=pstate
        self.puser=puser
        self.pimag=pimag


db.create_all()


#static file path
@app.route("/static/<path:path>")
def static_dir(path):
    return send_from_directory("static", path)

# home for every users, even the non-signed in
@app.route('/') 
def index():
    return render_template('index.html',Products=Products.query.all())

# create an account
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        password= request.form.get("password")
        repassword= request.form.get("repassword")
        if( password != repassword):
            flash("The passwords don't match")
            return redirect(url_for('signup'))

        fullname= request.form.get("fullname")
        username= request.form.get("username")
        # store in database
        new_user = User(fullname=fullname, username=username, password=generate_password_hash(password, method='sha256'))
        try:
            db.session.add(new_user)
            db.session.commit()
        except:
            flash('User already exist')
            return redirect(url_for('signup'))
        return redirect(url_for('followee'))
    return render_template('signUp.html')

# login
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username=request.form.get("username")   
        password=request.form.get("password")
        user = User.query.filter_by(username=username).first()
        # chech if the user already exist
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        login_user(user)
        session['username'] = username
        return redirect(url_for('home'))
    return render_template('signIn.html')


# logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username',None)
    return redirect(url_for('index'))

# home page for loged users
@app.route('/home')
@login_required
def home():
    return render_template("home.html",Products=Products.query.all())

# followee page
@app.route('/followee')
@login_required
def followee():
    username=session['username']    
    selected_user = User.query.filter_by(username=username).first_or_404()
    return render_template(
        'followee.html', 
    selected_user=selected_user)

# user progile page, he can modify and add post from here 
@app.route('/mypage')
@login_required
def mypage():
    username=session['username']
    return render_template('mypage.html', Products_my=Products.query.filter_by(puser=username))

# product detail page
@app.route('/product_detail/<pname>')
@login_required
def product_detail(pname):
    return render_template('product_detail.html',product_detail=Products.query.filter_by(pname=pname))

#add product
@app.route('/addproduct',methods=['POST','GET'])
@login_required
def addproduct():
    if request.method == 'POST':
        if not request.form['pname'] or not request.form['pdescript'] or not request.form['pkeyword']:
            flash('Please enter all the fields','error')
            return redirect(url_for('addproduct'))
        else: 
        # store in database
            puser=session['username']
            pstate='available'
            file = request.files['file']
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            pimag=filename
           # pstate='sell'
            new_product = Products(request.form['pname'],request.form['pdescript'], request.form['pkeyword'],request.form['pstate'],puser=puser,pimag=pimag)
            db.session.add(new_product)
            db.session.commit()
            flash('Product add success')
        return redirect(url_for('mypage'))
    return render_template('addproduct.html')


@app.route('/delete/<pname>')
@login_required
def delete(pname):
    product = Products.query.get_or_404(pname)
    
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('mypage'))  
    

@app.route('/edit/<pname>', methods=['POST','GET'])
@login_required
def edit(pname):
    product = Products.query.get_or_404(pname)

    if request.method == 'POST':
        product.pname = request.form['pname']
        product.pdescript = request.form['pdescript']
        product.pkeyword = request.form['pkeyword']
        if request.form['pstate'] == 'SOLD':
           product.pstate = request.form['pstate']
        else:
           product.pstate = request.form['pstate'] 

        try:
            db.session.commit()
            return redirect('/mypage')
        except:
            flash('There was an issue editing your post')
    return render_template('edit.html', product = product)

@app.route('/userpage/<username>')
def userpage(username):
    user = User.query.filter_by(username=username).first()
    me=session['username']
    if user.username == me:
        return render_template('mypage.html',Products_my=Products.query.filter_by(puser=username))
    else:
      return render_template('userpage.html',user=user)

@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot follow yourself!')
        return redirect(url_for('userpage', username=username))
    current_user.follow(user)
    db.session.commit()
    #flash('You are following {}!'.format(username))
    return redirect(url_for('userpage', username=username))


# username을 언팔로우 시도
@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot unfollow yourself!')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    #flash('You are not following {}.'.format(username))
    return redirect(url_for('userpage', username=username))


if __name__=='__main__':
    app.run(debug=True)