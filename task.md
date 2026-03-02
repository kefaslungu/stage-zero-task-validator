# **STAGE 0 — DEVOPS TRACK**

## **Task: Linux Server Setup & Nginx Configuration**

**Deadline: 48 hours from time of release. No extensions.**

---

## **Overview**

You will provision a Linux server, install and configure Nginx to serve two different locations, and secure it with a valid SSL certificate. No Docker, no Compose, no automation tools just a bare Linux server and your hands.

---

## **What You Must Do**

**1\. Server Setup**

Provision a Linux server (any cloud provider) and do the following:

* Create a non-root user called `hngdevops` with sudo privileges  
* Configure passwordless sudo for `hngdevops` for `/usr/sbin/sshd` and `/usr/sbin/ufw`  
* Disable root SSH login  
* Disable password-based SSH authentication — key-based only  
* Configure UFW to allow only ports 22, 80, and 443\. All other ports must be closed

**2\. Nginx Configuration**

Install Nginx and configure it to serve the following:

* `GET /` : serves a static HTML page that contains your HNG username visibly as text on the page  
* `GET /api` : returns the following JSON response exactly:

json  
{  
  "message": "HNGI14 Stage 0",  
  "track": "DevOps",  
  "username": "your-hng-username"  
}

`username` must match your registered HNG username exactly.

**3\. SSL**

Obtain a valid SSL certificate using Let's Encrypt (Certbot) for your domain and configure Nginx to serve both endpoints over HTTPS. HTTP requests must redirect to HTTPS with a `301`.

---

## **Tiny Technicalities**

* `/api` must return `Content-Type: application/json`  Nginx's `add_header` directive handles this  
* `/api` must return HTTP status `200`  
* The `username` field in the JSON must match your HNG registered username exactly, wrong casing fails  
* HTTP to HTTPS redirect must be a `301`, not a `302`  
* The SSL certificate must be a valid Let's Encrypt cert  self-signed certificates will fail the bot check  
* The static HTML page at `/` must contain your HNG username as visible text, hidden or commented-out text fails  
* Nginx must be the active web server    
* UFW must be active
* `hngdevops` must be able to run `sshd -T` and `ufw status` without a password prompt
* Sudoers example: `hngdevops ALL=(root) NOPASSWD:/usr/sbin/sshd,/usr/sbin/ufw`

---

## **Submission**

Submit the following in the form:

* Your live domain (e.g. `https://yourdomain.com`)  
* Your HNG username
