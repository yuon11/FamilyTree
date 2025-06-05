


const REGION = "us-east-1"; // Replace with your AWS region
const CLIENT_ID = "d99k4k51jutid3gfomqnkvk82"; // Replace with your Cognito User Pool App Client ID (no secret)
//     userPoolId: 'us-east-1_4nH4sgMeK', // replace with your User Pool ID

// login.js
window.onload = () => {
  const form = document.querySelector("loginForm");
  if (!form) return;

  form.addEventListener("submit", function (e) {
    e.preventDefault();

    const username = document.getElementById("Uname").value;
    const password = document.getElementById("Pword").value;

    AWS.config.region = REGION; // Replace with your AWS region

    const cognito = new AWS.CognitoIdentityServiceProvider();

    const params = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: "d99k4k51jutid3gfomqnkvk82", // Replace with your App Client ID (User Pool)
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
      },
    };

    cognito.initiateAuth(params, function (err, data) {
      if (err) {
        console.error("Login failed", err);
        alert("Login failed: " + err.message);

      } else {
        console.log("Login successful", data);
        alert("Login successful!");
        // You can save the tokens or redirect here
        // Example:
        // sessionStorage.setItem("idToken", data.AuthenticationResult.IdToken);
        // window.location.href = "dashboard.html";
      }
    });
  });
};
