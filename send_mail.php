<?php
/**
 * Villa del GARDA - Custom PHP Mailer
 * Sends lead data to multiple recipients without branding.
 */

// Allow cross-origin requests (for local testing)
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");

// --- SECURITY: RATE LIMITING (SESSIONS) ---
// This prevents one user from spamming the form too many times
session_start();
$limit_time = 600; // 10 minutes
$max_submissions = 5;

if (!isset($_SESSION['submission_count'])) {
    $_SESSION['submission_count'] = 0;
    $_SESSION['first_submission_time'] = time();
}

// Reset counter after limit time
if (time() - $_SESSION['first_submission_time'] > $limit_time) {
    $_SESSION['submission_count'] = 0;
    $_SESSION['first_submission_time'] = time();
}

// Check if limit exceeded
if ($_SESSION['submission_count'] >= $max_submissions) {
    http_response_code(429);
    echo json_encode(["status" => "error", "message" => "Too many submissions. Please try again later."]);
    exit;
}

// Only process POST requests
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Read the JSON input
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);

    if (!$data) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Invalid data received."]);
        exit;
    }

    // --- SECURITY: BOT PROTECTION (HONEYPOT) ---
    // If this field is filled, it's a bot
    if (!empty($data['website_url'])) {
        echo json_encode(["status" => "success", "message" => "Inquiry received (bot filtered)."]);
        exit;
    }

    // --- SECURITY: REFERER CHECK ---
    $allowed_host = 'hyrorealestate.com';
    $referer = isset($_SERVER['HTTP_REFERER']) ? parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) : '';
    // Allow local testing or check for domain match
    if ($referer && $referer !== $allowed_host && $referer !== '127.0.0.1' && $referer !== 'localhost') {
        http_response_code(403);
        echo json_encode(["status" => "error", "message" => "Forbidden: Unauthorized origin."]);
        exit;
    }

    // Sanitize inputs more rigorously
    $name = isset($data['name']) ? htmlspecialchars(strip_tags(trim($data['name'])), ENT_QUOTES, 'UTF-8') : 'N/A';
    $email = isset($data['email']) ? filter_var(trim($data['email']), FILTER_SANITIZE_EMAIL) : 'N/A';
    $phone = isset($data['phone']) ? preg_replace('/[^0-9+\-\s()]/', '', $data['phone']) : 'N/A';
    $unit = isset($data['unit_preference']) ? htmlspecialchars(strip_tags(trim($data['unit_preference'])), ENT_QUOTES, 'UTF-8') : 'Not Selected';
    $subject = isset($data['_subject']) ? htmlspecialchars(strip_tags(trim($data['_subject'])), ENT_QUOTES, 'UTF-8') : 'New Lead - Villa del GARDA';

    // Recipients
    $to = "kollusivababu2@gmail.com, developer@tadglobal.in";

    // Email Body Construction (Table Format)
    $email_content = "
    <html>
    <head>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; margin: 0; padding: 20px; background-color: #f9f9f9; }
            .container { background-color: #ffffff; padding: 40px; border-radius: 8px; max-width: 600px; margin: 0 auto; border-top: 6px solid #C9A86A; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
            .header { font-size: 22px; font-weight: bold; margin-bottom: 30px; color: #1F3A5F; text-align: center; letter-spacing: 1px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; border: 1px solid #E0D6C3; }
            th { background-color: #F9F7F4; color: #C9A86A; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; padding: 15px; text-align: left; border: 1px solid #E0D6C3; width: 35%; }
            td { padding: 15px; color: #142740; font-size: 14px; border: 1px solid #E0D6C3; }
            .footer { margin-top: 30px; font-size: 11px; color: #A0A0A0; text-align: center; border-top: 1px solid #EEE; padding-top: 20px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>VILLA DEL GARDA – NEW LEAD</div>
            
            <table>
                <tr>
                    <th>Source</th>
                    <td>$subject</td>
                </tr>
                <tr>
                    <th>Full Name</th>
                    <td>$name</td>
                </tr>
                <tr>
                    <th>Phone Number</th>
                    <td>$phone</td>
                </tr>
                <tr>
                    <th>Email Address</th>
                    <td><a href='mailto:$email' style='color: #1F3A5F; text-decoration: none;'>$email</a></td>
                </tr>
                <tr>
                    <th>Unit Preference</th>
                    <td>$unit</td>
                </tr>
            </table>

            <div class='footer'>
                This inquiry was sent from the Villa del GARDA Landing Page.<br>
                Time: " . date("Y-m-d H:i:s") . " (UTC)
            </div>
        </div>
    </body>
    </html>
    ";

    // Email Headers
    $from_email = "no-reply@hyrorealestate.com";
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= "From: Villa del GARDA <" . $from_email . ">" . "\r\n";
    $headers .= "Reply-To: $email" . "\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    // Send the email with the -f parameter for better deliverability on GoDaddy
    if (mail($to, $subject, $email_content, $headers, "-f " . $from_email)) {
        // Increment submission count for rate limiting
        $_SESSION['submission_count']++;
        echo json_encode(["status" => "success", "message" => "Thank you! Your inquiry has been sent."]);
    } else {
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Server error: Unable to send email."]);
    }

} else {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method not allowed."]);
}
?>