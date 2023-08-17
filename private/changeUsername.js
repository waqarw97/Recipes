// This is the event listener for the form submission
document.getElementById('username-form').addEventListener('submit', function(e) {
    // Preventing the default form submission behavior
    e.preventDefault();

    // Extracting the new username from the form
    const newUsername = document.getElementById('newUsername').value;

    // Confirming the action with the user
    const confirmed = confirm(`Are you sure you want to change your username to ${newUsername}?`);
    // If the user did not confirm the action, we stop here
    if (!confirmed) return;

    // Sending a POST request to the server to change the username
    fetch('/api/changeUsername', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        // Sending the new username in the request body
        body: JSON.stringify({ newUsername }),
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
