/**
 * NTML Authorisation Controller
 *
 * @description :: Server-side logic that returns the Windows Account User ID in Intranets.
 *				   Used to create a similar feature to Single Sign On.
 *				   This example is from a Sails.js controller in a Node.js stack.
 *
 * @author 		:: Glen Holmes
 * @help        :: See http://sailsjs.org/#!/documentation/concepts/Controllers
 */

module.exports = {
	ntlm : function(req, res) {
		// Get authorisation header
		var auth = req.headers.authorization;

		// If no authorisation method exists set to NTLM
		if (auth == undefined) {
	        res.status(401);
	        res.set('WWW-Authenticate', 'NTLM');
	        res.send();
	    }

	    // If/When authorisation data is available we can begin the 3 step authorisation process
	    if (auth != undefined) {

	    	// Create a buffer to hold the authorisation stage
	    	var buf = new Buffer(auth.substring(5), 'base64');

	    	// Check what step of authorisation process we are
	    	// If we are at step one
	    	if (buf[8] == 1) { 
	    		var off = 0, length, offset;
	    		var s;

	    		off = 18;

	    		// Set the buffer to request the NTLM
	    		var buf1 = new Buffer('4e544c4d535350000200000000000000280000000182000000020202000000000000000000000000', 'hex');
	    		//						N  T  L  M  S  S  P  0  2  0  0  0  0  0  0  0 40  0  0  0  1130  0  0  0  2  2  2  0  0  0  0  0  0  0  0  0  0  0  0
	    		
	    		// Convert the buffer to base64
	    		buf1 = buf1.toString('base64');

	    		// Send response looking for NTLM response (This response is step two)
	    		res.status(401);
	        	res.set('WWW-Authenticate', 'NTLM ' + buf1);
	        	res.send();
	        } 
	        // If we are at step three
	        else if (buf[8] == 3) {

	        	// Get the buffer in ASCII format
	        	var user = buf.toString("ascii");

	        	// For internet explorer users we are looking to start from position 100 of the array

	  			// In this example I know corporate ID's are six digits long and can therefore create a substring holding just the ID
	  			// It is worth noting that the ID is spaced out by blank characters, you can skip them as I have or use .trim to trim blank spaces.

	        	if(user[100] != null){
	                user = user.substring(100,114);
	                user = user[0]+user[2]+user[4]+user[6]+user[8]+user[10]+user[12];
	                user = user.toUpperCase();
	        	} 

	        	// This will display the user name
	        	console.log("User: " + user);

	        	// In this example we check does the user ID exist in the database before giving access.
	        	// It is worth noting that this is used to provide access to non sensitive internal data and designed as a simple NTML hack
                
                User.findOne(user, function (err, user) {
					if (err) {
						req.session.flash = {
							err: ['Error finding your user']
						}
						res.redirect('/session/new');
						return;
					}
					// user does not exist
					if(!user) {
						req.session.flash = {
							err: ['Your user does not exist in our database']
						}
						res.redirect('/session/new')
						return;
					}
					// create session
					req.session.authenticated = true;
					req.session.User = user;

					// 
					res.redirect('/user/'+user.id);
				});
	        }
	        else {
	        	res.redirect("/session/new");
	        }
	    }
	}
};

