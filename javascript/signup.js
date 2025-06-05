// auth.js
// function getSecretHash(username, clientId, clientSecret) {
//   return crypto
//     .createHmac("sha256", clientSecret)
//     .update(`${username}${clientId}`)
//     .digest("base64");
// }

window.onload = () => {
  const form = document.getElementById("signUpForm");
  //DEBUG
  console.log("start of sign p json 1")
  // console.log(form)
  //DEBUG

  if (!form) return;

  //DEBUG
  console.log("start of sign p json 2")
  //DEBUG

  form.addEventListener("submit", function (e) {
    e.preventDefault();

    //DEBUG
    console.log("Submit button listener")
    //DEBUG

    const username = document.getElementById("Uname").value;
    const email = document.getElementById("Email").value;
    const password = document.getElementById("Pword").value;
    const confirmPassword = document.getElementById("Pword_Confirm").value;
    const clientID = "1auk0sj6ee0a4kpi2h4h95bqd3"

    if (password !== confirmPassword) {
      alert("Passwords do not match.");
      return;
    }

    AWS.config.region = "us-east-1"; // Replace with your region

    AWS.config.credentials = new AWS.CognitoIdentityCredentials({
      IdentityPoolId: "us-east-1_4nH4sgMeK", // optional if you just need user pool
    });

    const cognito = new AWS.CognitoIdentityServiceProvider();

    const params = {
      ClientId: clientID, // Replace with your User Pool App Client ID
      Username: username,
      Password: password,
      UserAttributes: [
        {
          Name: "name",
          Value: username,
        },
        {
          Name: "email",
          Value: email,
        },
        {
          Name: "nickname",
          Value: username,
        }
      ],
    };

    //DEBUG
    console.log("POST AWS object creation")
    //DEBUG

    cognito.signUp(params, function (err, data) {
      if (err) {
        console.error("Sign up error", err);
        alert("Sign up failed: " + err.message);
      } else {
        console.log("Sign up success", data);
        alert("Account created! Please check your email to verify.");
      }
    });

    //DEBUG
    console.log("END OF SIGNUP FUNCITON")
    //DEBUG
  });
};
