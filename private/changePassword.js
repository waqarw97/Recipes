// This is the event listener for the form submission
document.getElementById('password-form').addEventListener('submit', function (e) {
    // Preventing the default form submission behavior
    e.preventDefault();

    // Extracting the old and new password from the form
    const oldPassword = document.getElementById('oldPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    // Extracting the confirmation password
    const newPasswordConfirmation = document.getElementById('newPasswordConfirmation').value;

    // Check if new password and its confirmation match
    if (newPassword !== newPasswordConfirmation) {
        alert("New password and its confirmation don't match!");
        return; // Stop here and don't submit the form
    }

    // Sending a POST request to the server to change the password
    fetch('/api/changePassword', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        // Sending the old and new password in the request body
        body: JSON.stringify({
            oldPassword,
            newPassword,
            newPasswordConfirmation // Including the confirmation in the request
        }),
        credentials: 'include' // This line is added to include cookies in request
    })
    .then(response => response.json())
    .then(data => {
        if (data.errors) {
            // If there are errors, display the first error message
            alert(data.errors[0].msg);
        } else {
            // If no errors, redirect to the profile page
            window.location.href = '/private/profile.html';
        }
    })
    .catch((error) => {
        // Logging any errors that occurred
        console.error('Error:', error);
    });
});
