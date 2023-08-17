// Make a GET request to fetch the logged in user's profile data
fetch('/api/profile', {credentials: 'include'})  
.then(response => response.json())
.then(user => {
    // When the data is received, populate the page with it
    document.getElementById('username').textContent = 'Username: ' + user.username;
    document.getElementById('email').textContent = 'Email: ' + user.email;
})
.catch(err => {
    // If an error occurred (like the user not being logged in), log it and redirect to the login page
    console.error(err);
    window.location.href = '/login.html';
});

// Add event listener to the "Change Username" button
document.getElementById('changeUsernameBtn').addEventListener('click', function() {
    // When the button is clicked, redirect to the "Change Username" page
    window.location.href = '/changeUsername';
});

// Add event listener to the "Change Email" button
document.getElementById('changeEmailBtn').addEventListener('click', function() {
    // When the button is clicked, redirect to the "Change Email" page
    window.location.href = '/changeEmail';
});

// Add event listener to the "Change Password" button
document.getElementById('changePasswordBtn').addEventListener('click', function() {
    // When the button is clicked, redirect to the "Change Password" page
    window.location.href = '/changePassword';
});

document.getElementById('logoutBtn').addEventListener('click', function() {
    // When the button is clicked, send a GET request to log out
    fetch('/logout', {
        credentials: 'include',
    })
    .then(response => response.json())
    .then(data => {
        // If the logout was successful, redirect to the login page
        if (data.success) {
            window.location.href = '/login.html';
        } else {
            // If an error occurred, log it
            console.error('Error occurred during logout: ', data.message);
        }
    })
    .catch(err => {
        // If an error occurred, log it
        console.error('Error occurred during logout: ', err);
    });
});


// Add event listener to the "Delete Account" button
document.getElementById('deleteAccountBtn').addEventListener('click', function() {
    // Ask the user to confirm that they want to delete their account
    if (!confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
        return;
    }

    // When the button is clicked, send a DELETE request to delete the account
    fetch('/api/deleteAccount', {
        method: 'DELETE',
        credentials: 'include',
    })
    .then(response => {
        // If the account deletion was successful, redirect to the login page
        if (response.ok) {
            window.location.href = '/login.html';
        } else {
            // If an error occurred, log it
            console.error('Error occurred during account deletion: ', response.statusText);
        }
    })
    .catch(err => {
        // If an error occurred, log it
        console.error('Error occurred during account deletion: ', err);
    });
});
