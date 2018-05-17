#! /usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import make_response
from flask import Flask, Response, request, session, url_for, redirect, json
import base64
import os


dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database.db"

app = Flask(__name__, static_url_path="/")
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
app.secret_key = 'esto-es-una-clave-muy-secreta'


class Users(db.Model):
	id_user = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique=True, nullable=False)
	password = db.Column(db.String(80), nullable=False)
	profile = db.Column(db.Integer, nullable=False)

class Scan(db.Model):
	id_scan = db.Column(db.Integer, primary_key=True)
	ssid = db.Column(db.String(50),  nullable=False)
	channel = db.Column(db.String(50),  nullable=False)
	encryption = db.Column(db.String(50), nullable=False)
	ssid_password = db.Column(db.String(50),  nullable=False)
	date = db.Column(db.String(50), nullable=False)
	id_user1 = db.Column(db.Integer, nullable=False)
	

@app.route('/', methods=["GET", "POST"])
def login():
	if request.method == "POST":

		user = Users.query.filter_by(username=request.form["username"]).first()
		if user and check_password_hash(user.password, request.form["password"]):
			session['logueado'] = "si"
			session['userlogueado'] = request.form["username"]
			return redirect("/dashboard")
		return "Tus credenciales son invalidas,revisa e intenta nuevamente"
	return render_template('login.html')

@app.route('/signup', methods=["GET", "POST"])
def signup():
	if request.method == "POST":	
		hashed_pw = generate_password_hash(request.form["password"], method="sha256")
		new_user = Users(username=request.form["username"], password=hashed_pw, profile=request.form["profile"])
		db.session.add(new_user)
		db.session.commit()
		return "Has sido registrado correctamente"
		return render_template("signup.html")
	return redirect("/error")

@app.route("/dashboard" , methods=["GET", "POST"])
def dashboard():
	if session:
		return Response('''
<html>
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>	
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.3/css/bootstrap.min.css" integrity="sha384-Zug+QiDoJOrZ5t4lssLdxGhVrurbmBWopoEl+M6BdEfwnCJZtKxi1KgxUyJq13dy" crossorigin="anonymous">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0-beta/css/materialize.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0-beta/js/materialize.min.js"></script>
<link href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" rel="stylesheet" integrity="sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN" crossorigin="anonymous">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.12.1/bootstrap-table.min.css" />
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.12.1/bootstrap-table.min.js"></script>

</head>
<body>


					<nav>
						<div class="nav-wrapper blue lighten-1">
						  <a href="dashboard" class="brand-logo" style='margin-left: 10px;'>Dashboard</a>
						  <ul id="nav-mobile" class="right hide-on-med-and-down">
							<li></li>
							<li><input type="button" name="Attack" value="Attack" class="btn btn-danger" onclick="commands_attacks()">
							<li><a href="logout" ><i class='fa fa-sign-out fa-2x'></i></a></li>
						  </ul>
						</div>
					</nav>
					<div class='row' '''+ "style" +'''>
						<div class='col-md-8 offset-2 text-center'>
							<h4 class='grey-text'>Results</h4>


<table id="userTable" 
data-url="results" 
data-show-refresh="true"
data-height="500"
data-search="true"
class='table'>
<thead>
<tr>
<th data-field="id" data-formatter="table.tools" data-width="0"></th>
<th data-field="BSSID">BSSID</th>
<th data-field="CIPHER">CIPHER</th>
<th data-field="ESSID">ESSID</th>
<th data-field="PASSWORD">PASSWORD</th>
<th data-field="WPS">WPS</th>
</tr>
</thead>
</table>


<script>
					var table = {};
					table.actions = {};
					table.actions.edit = function(id) { alert('default edit for id: ' + id); };
					table.actions.delete = function(id) { alert('default delete for id: ' + id); };
					table.role_formatter = function(value, row, index){return (value == 1)?"Administrator":"User";};
					table.tools = function(value, row, index){
						return "<a title='edit' class='btn btn-default grey darken-1 white-text' onclick='table.actions.edit("+value+");'><i class='fa fa-pencil'></i></a>"
							+ "<a title='remove' class='btn btn-danger grey darken-5 white-text' onclick='table.actions.delete("+value+");'><i class='fa fa-trash'></i></a>";
					};
					$(document).ready(function(){
						$("#userTable").bootstrapTable();
					});
				</script>


<script>
function commands_attacks()
{
   $.ajax({
     type: "POST",
     url: "http://127.0.0.1:5000/commands",
     data: 1,
      
   });
   }
</script>


</body>
</html>'''	)


		#return render_template("dashboard.html")
	return redirect("/error")

@app.route('/results')	
def results():
	if session:
		data=[]
		with open('cracked.csv','r') as f:
			for i in f.readlines():
				row=i.split(',')
				target=dict()
				target['BSSID']=row[0]
				target['CIPHER']=row[1]
				target['ESSID']=row[2]
				target['PASSWORD']=row[3]
				target['WPS']=row[4]
				data.append(target)
		return app.response_class(
			response=json.dumps(data),
			status=200,
			mimetype="application/json"
		)
		
		 	
	#return redirect("/error")

@app.route('/error')
def error():
	return render_template("error.html")

@app.route('/tabla')
def tabla():
	return render_template("tabla.html")

@app.route('/tables')
def tables():
	return render_template("tables.html")

@app.route('/commands', methods=["GET", "POST"])
def commands():
	if session:

		if request.method=="POST":
			os.system('sudo python ghost.py --aircrack -dict dict.lst')
	return redirect("/error")

	
if __name__=='__main__':
	db.create_all()
	app.run(debug = True, port = 5000)
