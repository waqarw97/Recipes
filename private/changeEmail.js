// This is the event listener for the form submission
document.getElementById('email-form').addEventListener('submit', function(e) {
    // Preventing the default form submission behavior
    e.preventDefault();

    // Extracting the new email from the form
    const newEmail = document.getElementById('newEmail').value;

    // Confirming the action with the user
    const confirmed = confirm(`Are you sure you want to change your email to ${newEmail}?`);
    // If the user did not confirm the action, we stop here
    if (!confirmed) return;

    // Sending a POST request to the server to change the email
    fetch('/api/changeEmail', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        // Sending the new email in the request body
        body: JSON.stringify({ newEmail }),
        credentials: 'include'   // This line is added to include cookies in request
    })
    .then(response => response.text())
    .then(data => {
        // Displaying the server's response in an alert
        alert(data);
        // Redirecting the user back to their profile page
        window.location.href = '/private/profile.html';
    })
    .catch((error) => {
        // Logging any errors that occurred
        console.error('Error:', error);
    });
});
