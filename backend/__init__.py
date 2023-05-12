from flask import Flask, g , request
from flask_mongoengine import MongoEngine
from flask_cors import CORS
import time
import os
from csbt.src.util.cache import cache
from csbt.src.util.models import db, add_if_no_user_exist
#Defining flask app
template_dir = os.path.abspath('./templates');
app = Flask(__name__,template_folder=template_dir)
CORS(app)

app.config.from_pyfile('./src/config/mongo_config.cfg')
app.config['SECRET_KEY'] = 'csbt_project'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME']='stuti707@gmail.com'
app.config['MAIL_PASSWORD']='Stuti@123'
app.config['USE_SSL']=True
app.config['USE_TLS']=True
app.config['SERVER_URL'] = "localhost:4200/#/"
#db = MongoEngine(app)
cache.init_app(app)
db.init_app(app)

#importing blueprint
from csbt.src.apis.metadata_apis import metadata
from csbt.src.apis.crf_apis import crf
from csbt.src.apis.study_apis import study
from csbt.src.apis.ml_apis import ml
from csbt.src.apis.user_mgnt_apis import user_management
from csbt.src.apis.test_case_automation_apis import test_case_automation
from csbt.src.apis.sdtm_apis import sdtm
from csbt.src.apis.custom_sdtm_mapping_apis import custom_mapping
from csbt.src.apis.sdtm_codelist_apis import sdtm_codelists

#registering blueprint
app.register_blueprint(metadata)
app.register_blueprint(crf)
app.register_blueprint(study)
app.register_blueprint(ml)
app.register_blueprint(user_management)
app.register_blueprint(test_case_automation)
app.register_blueprint(sdtm)
app.register_blueprint(custom_mapping)


add_if_no_user_exist()

app.register_blueprint(sdtm_codelists)
		



@app.before_request
def before_request():
	g.start = time.time()
	g.path = request.path


@app.after_request
def after_request(response):
	
	diff = time.time() - g.start
	print("\n\n=============" + request.method + " : "+ g.path+" : " +str(diff)+"===========\n\n")
	return response
	
