from flask import Flask, render_template, request
import os
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

@app.route("/analysis", methods=['GET', 'POST'])
def run():
	return render_template("analysis.html")



@app.route("/submit", methods = ['GET', 'POST'])
def get_output():
	if request.method == 'POST':
		img = request.files['image_input']
		url = request.form['url_input']
		if img.filename != "":
			img_path = "static/" + img.filename	
			img.save(img_path)
			filename = os.path.join(os.path.dirname("static/"), img.filename)
			string = 'exiftool/exiftool -j ' + filename
			metaInfo = os.popen(string).read()
			metaInfo = json.loads(metaInfo)
			fileResult = {}
			fileResult['metaInfo'] = metaInfo
			fileResult['md5'] = "0bfb331611cbcf420b38f73e1936f836"
			if "PEType" in metaInfo[0]:
				try:
					pefile.PE(filename)
					fileResult['peInfoMalicious'] = pe_test.predictMalicious(filename)
					fileResult['type'] = 1
				except:
					fileResult['peInfoMalicious'] = {}
					fileResult['type'] = 1
			elif metaInfo[0]["FileType"] == "JPEG":
				fileResult['JPGMalicious']= JPEG_test.check_JPG_malicious(filename)
				fileResult['type'] = 2
			return render_template("result.html", prediction = fileResult)
		else:
			urlResult = {}
			urlResult['cert_info'] = url_ssl_verf.url_cert_info(url)
			urlResult['phishing_info']=phishing.check_URL_malicious(url)
			urlResult['type'] = 3
			return render_template("result.html", prediction = urlResult)

if __name__ =='__main__':
	#app.debug = True
	app.run(debug = True)