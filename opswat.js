const fs = require('fs');
var crypto = require('crypto');
var http = require("https");
var request = require('request');

var EventEmitter = require("events").EventEmitter;
var getHashEvent = new EventEmitter();
var findHashEvent = new EventEmitter();
var uploadEvent = new EventEmitter();
var pullEvent = new EventEmitter();

var file = process.argv[2];
var key = "key goes in here"; //please use your api key to replace inside the quotes

if(!file){
	console.log("Please enter your file name!");
	return;
} 
else if (!fs.existsSync(file)) {
    console.log("The file you selected does not exist!");
    return;
}

getHash(file);  //call get hash function to get response and emit to get Hash event

getHashEvent.on('getHashEvent', function () {  
  //console.log(getHashEvent.data);  //print the hash to check

  usingHash(getHashEvent.data, key);  // call using hash function to get reponse and emit to hash event

  findHashEvent.on('findHashEvent', function () {  //hash event call
    let json = JSON.parse(findHashEvent.data);

    if(!json.data_id){                          //if data id does not exist, need to upload file and then pull results
        uploadFile(file,key);                  // call upload function to upload a file and emit to upload event

        uploadEvent.on('uploadEvent', function(){       //upload event call
           let json = JSON.parse(uploadEvent.data);
           //console.log(json.data_id);              //print the data_id to check
           pullResults(json.data_id, key);       // call pull function to pull result emit to pull event

           pullEvent.on('pullEvent', function(){       //pull event call
             let json = JSON.parse(pullEvent.data);
             if(json.file_id){
                    display(json);         //display the results
             }

             else{
             	pullResults(json.data_id,key);
             }
           });
        });
    }

    else{                                             //data id exists, just pull the results 
    	//console.log("exits!")  //print to check file exits or not
    	pullResults(json.data_id, key); 
    	pullEvent.on('pullEvent', function(){       //pull event call
             let json = JSON.parse(pullEvent.data);
             if(json.file_id){
                    display(json);         //display the results
             }

             else{
             	pullResults(json.data_id,key);
             }
         });
    }

  });
});


//function to hash a file and return the hash as string
function getHash(file) {
  var fd = fs.createReadStream(file);
  var hash = crypto.createHash('sha256');
  hash.setEncoding('hex');

  fd.on('end', function() {
    hash.end();
    getHashEvent.data = hash.read(); 
    getHashEvent.emit('getHashEvent');
  });

  // read all file and pipe it (write it) to the hash object
  fd.pipe(hash);
};

//function to call opswat api to retrive scan report using a hash, and emit reponse as string to hash event
function usingHash(hash, key) {
   var options = {
	  "method": "GET",
	  "hostname": "api.metadefender.com",
	  "port": null,
	  "path": "/v2/hash/" + hash,
	  "headers": {
	    "apikey": key
	  }
	};
 
	var req = http.request(options, function (res) {
	  var chunks = [];
 
	  res.on("data", function (chunk) {
	    chunks.push(chunk);
	  });
 
	  res.on("end", function () {
	    var body = Buffer.concat(chunks);
	    findHashEvent.data = body.toString();
	    findHashEvent.emit('findHashEvent');
	  });
	});
 
	req.end();
};

//function to call opswat api to upload a file, and emit reponse as string to upload event
function uploadFile(file, key){
  var formData = {
	  file: fs.createReadStream(__dirname + '/' + file)
  };
 
	request.post({
			url: 'https://api.metadefender.com/v2/file',
			formData: formData,
			headers: {
				apikey: key
			}
		},
		function(err, httpResponse, body) {
			if (err) {
				return console.error('upload failed:', err);
			}
			uploadEvent.data = body.toString();
            uploadEvent.emit('uploadEvent');
		}
	);
};

//function to call opswat api to retrive scan report using a data id, and emit reponse as string to pull event
function pullResults(dataId, key){
  var options = {
	  "method": "GET",
	  "hostname": "api.metadefender.com",
	  "port": null,
	  "path": "/v2/file/" + dataId,
	  "headers": {
	    "apikey": key
	  }
	};
 
	var req = http.request(options, function (res) {
	  var chunks = [];
 
	  res.on("data", function (chunk) {
	    chunks.push(chunk);
	  });
 
	  res.on("end", function () {
	    var body = Buffer.concat(chunks);
	    pullEvent.data = body.toString();
	    pullEvent.emit('pullEvent');
	  });
	});
 
	req.end();
};

//function to display the results
function display(results){
  console.log('filename: ' + file);
  console.log('overall_status: ' + results.scan_results.scan_all_result_a);

  const scans = results.scan_results.scan_details;
  for (var i in scans) {
    console.log('');
    console.log('engine: ' + i);
    console.log('threat_found: ' + (scans[i].threat_found? scan[i] : 'None'));
    console.log('scan_result: ' + scans[i].scan_result_i);
    console.log('scan_time: ' + scans[i].scan_time);
    console.log('def_time: ' + scans[i].def_time);
  }
  console.log('');
  console.log('END');
}


