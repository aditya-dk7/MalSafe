from flask import Flask, render_template, request
import os
from flask import jsonify
from flask_restful import Api, Resource
import base64
import pefile
import URLModule.url_ssl_verf as url_ssl_verf
import PEModule.pe_test as pe_test
import json
import JPEGModule.JPEG_test as JPEG_test
import URLModule.phishing as phishing

app = Flask(__name__)

# routes
@app.route("/", methods=['GET', 'POST'])
def main():
	return render_template("index.html")

@app.route("/static/analysis.html", methods=['GET', 'POST'])
def run():
	return render_template("analysis.html")



@app.route("/submit", methods = ['GET', 'POST'])
def get_output():
	if request.method == 'POST':
		img = request.files['my_image']

		img_path = "static/" + img.filename	
		img.save(img_path)
		filename = os.path.join(os.path.dirname("static/"), img.filename)
		string = 'exiftool/exiftool -j ' + filename
		metaInfo = os.popen(string).read()
		print(metaInfo)
		metaInfo = json.loads(metaInfo)
		fileResult = {}
		fileResult['metaInfo'] = metaInfo
		fileResult['md5'] = "0bfb331611cbcf420b38f73e1936f836"
		if "PEType" in metaInfo[0]:
			try:
				pefile.PE(filename)
				fileResult['peInfoMalicious'] = pe_test.predictMalicious(filename)
			except:
				fileResult['peInfoMalicious'] = {}
		elif metaInfo[0]["FileType"] == "JPEG":
			fileResult['JPGMalicious']= JPEG_test.check_JPG_malicious(filename)
	return render_template("index.html", prediction = fileResult, img_path = img_path)


if __name__ =='__main__':
	#app.debug = True
	app.run(debug = True)