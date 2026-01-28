<?php
/**
 * ============================================================================
 * DIRECTORY EXPLORER - Temporary Utility
 * ============================================================================
 * 
 * PURPOSE: Explore your server's directory structure to find correct paths
 *          for configuring Security Sentinel.
 * 
 *  DELETE THIS FILE AFTER USE - It's a security risk to leave it on your server!
 * 
 * Usage:
 *   1. Upload to your server
 *   2. Access via browser
 *   3. Enter the password below
 *   4. Browse directories and copy paths
 *   5. DELETE THIS FILE when done
 * 
 * @version 1.0.0
 */

// ============================================================================
// CONFIGURATION - Change this password!
// ============================================================================
$PASSWORD = 'change-this-password-before-uploading'; // CHANGE THIS before uploading!

// ============================================================================
// SECURITY
// ============================================================================
session_start();

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");

// CSRF Token
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

// ============================================================================
// AUTHENTICATION
// ============================================================================
$error = null;

if (isset($_POST['password'])) {
    if ($_POST['csrf'] !== $_SESSION['csrf']) {
        $error = "Invalid request";
    } elseif ($_POST['password'] === $PASSWORD) {
        $_SESSION['explorer_auth'] = true;
        session_regenerate_id(true); // Prevent session fixation
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        sleep(2); // Slow down brute force
        $error = "Invalid password";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Show login if not authenticated
if (empty($_SESSION['explorer_auth'])) {
    showLogin($error);
    exit;
}

// ============================================================================
// FILE VIEWER ACTION
// ============================================================================
if (isset($_GET['action']) && $_GET['action'] === 'view_file' && isset($_GET['file'])) {
    $fileToView = realpath($_GET['file']);
    
    // Validate path
    if ($fileToView && file_exists($fileToView) && is_file($fileToView)) {
        
        // Security check (reusing block logic if implemented, or basic sanity check)
        // Just ensuring we don't read outside allowed areas if specific logic existed
        // For now, relying on authentication
        
        $mime = mime_content_type($fileToView);
        $content = file_get_contents($fileToView);
        
        // Simple heuristic for text files
        $isText = strpos($mime, 'text') !== false || 
                  strpos($mime, 'json') !== false ||
                  strpos($mime, 'xml') !== false ||
                  pathinfo($fileToView, PATHINFO_EXTENSION) === 'php' ||
                  pathinfo($fileToView, PATHINFO_EXTENSION) === 'env';
                  
        if ($isText) {
            echo json_encode(['success' => true, 'content' => $content, 'path' => $fileToView]);
        } else {
            echo json_encode(['success' => false, 'error' => 'Binary files cannot be viewed inline.']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'File not found or invalid.']);
    }
    exit;
}

// ============================================================================
// DIRECTORY BROWSING
// ============================================================================

// Get current path
$currentPath = isset($_GET['path']) ? $_GET['path'] : __DIR__;
$currentPath = realpath($currentPath);

// Security: Prevent accessing sensitive system directories (optional - comment out if needed)
$blockedPaths = []; // Add paths to block if needed: ['/etc/shadow', '/root']

foreach ($blockedPaths as $blocked) {
    if (strpos($currentPath, $blocked) === 0) {
        $currentPath = __DIR__;
        break;
    }
}

// If path doesn't exist, fall back to script directory
if (!$currentPath || !file_exists($currentPath)) {
    $currentPath = __DIR__;
}

// Get directory contents
$items = [];
$error_msg = null;

if (is_dir($currentPath) && is_readable($currentPath)) {
    $entries = @scandir($currentPath);
    if ($entries !== false) {
        foreach ($entries as $entry) {
            if ($entry === '.') continue;
            
            $fullPath = $currentPath . DIRECTORY_SEPARATOR . $entry;
            $isDir = is_dir($fullPath);
            $isReadable = is_readable($fullPath);
            $isWritable = is_writable($fullPath);
            
            $size = 0;
            $modified = 0;
            $perms = '----';
            
            if (file_exists($fullPath)) {
                $size = $isDir ? 0 : @filesize($fullPath);
                $modified = @filemtime($fullPath);
                $perms = @substr(sprintf('%o', fileperms($fullPath)), -4);
            }
            
            $items[] = [
                'name' => $entry,
                'path' => $fullPath,
                'is_dir' => $isDir,
                'is_readable' => $isReadable,
                'is_writable' => $isWritable,
                'size' => $size,
                'modified' => $modified,
                'perms' => $perms,
            ];
        }
        
        // Sort: directories first, then alphabetically
        usort($items, function($a, $b) {
            if ($a['name'] === '..') return -1;
            if ($b['name'] === '..') return 1;
            if ($a['is_dir'] && !$b['is_dir']) return -1;
            if (!$a['is_dir'] && $b['is_dir']) return 1;
            return strcasecmp($a['name'], $b['name']);
        });
    } else {
        $error_msg = "Cannot read directory contents";
    }
} else {
    $error_msg = "Path is not a directory or not readable";
}

// Get path segments for breadcrumb
$pathSegments = explode(DIRECTORY_SEPARATOR, $currentPath);
$pathSegments = array_filter($pathSegments);

// Get server info
$serverInfo = [
    'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'N/A',
    'script_dir' => __DIR__,
    'script_file' => __FILE__,
    'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
    'php_version' => phpversion(),
    'os' => PHP_OS,
    'user' => get_current_user(),
];

// Extended Server Stats
$serverStats = [
    'php_limits' => [
        'memory_limit' => ini_get('memory_limit'),
        'post_max_size' => ini_get('post_max_size'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'max_execution_time' => ini_get('max_execution_time') . 's',
        'max_input_vars' => ini_get('max_input_vars'),
    ],
    'disk' => [
        'free' => @disk_free_space($currentPath),
        'total' => @disk_total_space($currentPath),
    ],
    'extensions' => get_loaded_extensions(),
    'opcache' => function_exists('opcache_get_status') ? opcache_get_status(false) : false,
];
sort($serverStats['extensions']);

// Calculate disk percentage
$diskPercent = 0;
if ($serverStats['disk']['total'] > 0) {
    $used = $serverStats['disk']['total'] - $serverStats['disk']['free'];
    $diskPercent = round(($used / $serverStats['disk']['total']) * 100, 1);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function formatBytes($bytes) {
    if ($bytes === 0) return '-';
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = floor(log($bytes, 1024));
    return round($bytes / pow(1024, $i), 2) . ' ' . $units[$i];
}

function getFileIcon($item) {
    if ($item['name'] === '..') return 'fa-level-up-alt';
    if ($item['is_dir']) return 'fa-folder';
    
    $ext = strtolower(pathinfo($item['name'], PATHINFO_EXTENSION));
    
    $icons = [
        'php' => 'fa-file-code text-purple',
        'html' => 'fa-file-code text-orange',
        'htm' => 'fa-file-code text-orange',
        'css' => 'fa-file-code text-info',
        'js' => 'fa-file-code text-warning',
        'json' => 'fa-file-code text-warning',
        'xml' => 'fa-file-code text-success',
        'sql' => 'fa-database text-primary',
        'txt' => 'fa-file-alt',
        'md' => 'fa-file-alt',
        'log' => 'fa-file-alt text-muted',
        'jpg' => 'fa-file-image text-success',
        'jpeg' => 'fa-file-image text-success',
        'png' => 'fa-file-image text-success',
        'gif' => 'fa-file-image text-success',
        'svg' => 'fa-file-image text-success',
        'webp' => 'fa-file-image text-success',
        'pdf' => 'fa-file-pdf text-danger',
        'zip' => 'fa-file-archive text-warning',
        'tar' => 'fa-file-archive text-warning',
        'gz' => 'fa-file-archive text-warning',
        'rar' => 'fa-file-archive text-warning',
        'env' => 'fa-lock text-danger',
        'htaccess' => 'fa-shield-alt text-danger',
        'htpasswd' => 'fa-shield-alt text-danger',
    ];
    
    // Check for dotfiles
    if (strpos($item['name'], '.') === 0) {
        return 'fa-file-alt text-muted';
    }
    
    return isset($icons[$ext]) ? 'fa-file ' . $icons[$ext] : 'fa-file';
}

function showLogin($error) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="robots" content="noindex, nofollow">
        <title>Directory Explorer</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-card {
                background: rgba(255,255,255,0.05);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 16px;
                padding: 40px;
                width: 100%;
                max-width: 400px;
                color: #fff;
            }
            .form-control {
                background: rgba(255,255,255,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                color: #fff;
            }
            .form-control:focus {
                background: rgba(255,255,255,0.15);
                border-color: #0d6efd;
                color: #fff;
                box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.25);
            }
            .form-control::placeholder { color: rgba(255,255,255,0.5); }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="text-center mb-4">
                <div class="display-4 mb-2">📁</div>
                <h4>Directory Explorer</h4>
                <p class="small" style="color: #cbd5e1;">Temporary utility - delete after use!</p>
            </div>
            
            <?php if ($error): ?>
                <div class="alert alert-danger py-2"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <form method="post">
                <input type="hidden" name="csrf" value="<?php echo $_SESSION['csrf']; ?>">
                <div class="mb-3">
                    <input type="password" name="password" class="form-control" placeholder="Password" required autofocus>
                </div>
                <button type="submit" class="btn btn-primary w-100">Enter</button>
            </form>
            
            <div class="alert alert-warning mt-4 mb-0 small">
                <strong> Security Warning:</strong><br>
                Delete this file immediately after finding your paths!
            </div>
        </div>
    </body>
    </html>
    <?php
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>Directory Explorer</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --border-color: #475569;
            --text-primary: #f8fafc;
            --text-muted: #cbd5e1;
            --text-light: #e2e8f0;
            --accent: #60a5fa;
        }
        
        * { box-sizing: border-box; }
        
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            margin: 0;
        }
        
        .navbar {
            background: var(--bg-card) !important;
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
        }
        
        .navbar-brand {
            font-weight: 600;
            color: var(--text-primary) !important;
        }
        
        .container-fluid {
            padding: 24px;
            max-width: 1600px;
        }
        
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            color: white!important;
        }
        
        .card-header {
            background: transparent;
            border-bottom: 1px solid var(--border-color);
            padding: 16px 20px;
            font-weight: 600;
        }
        
        /* Breadcrumb */
        .path-breadcrumb {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 4px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        
        .path-breadcrumb a {
            color: var(--accent);
            text-decoration: none;
        }
        
        .path-breadcrumb a:hover {
            text-decoration: underline;
        }
        
        .path-breadcrumb .separator {
            color: var(--text-light);
            margin: 0 4px;
        }
        
        .path-breadcrumb .current {
            color: var(--text-primary);
            font-weight: 500;
        }
        
        /* Copy button */
        .copy-path-btn {
            background: var(--accent);
            border: none;
            color: white;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            margin-left: auto;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }
        
        .copy-path-btn:hover {
            background: #2563eb;
        }
        
        .copy-path-btn.copied {
            background: #10b981;
        }
        
        /* File list */
        .file-list {
            border-radius: 12px;
            overflow: hidden;
        }
        
        .file-item {
            display: grid;
            grid-template-columns: auto 1fr auto auto auto auto;
            gap: 16px;
            padding: 12px 20px;
            border-bottom: 1px solid var(--border-color);
            align-items: center;
            transition: background 0.15s;
        }
        
        .file-item:last-child {
            border-bottom: none;
        }
        
        .file-item:hover {
            background: rgba(59, 130, 246, 0.05);
        }
        
        .file-item.is-dir {
            cursor: pointer;
        }
        
        .file-icon {
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            font-size: 1rem;
        }
        
        .file-icon.folder {
            background: rgba(251, 191, 36, 0.15);
            color: #fbbf24;
        }
        
        .file-name {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .file-name a {
            color: var(--text-primary);
            text-decoration: none;
        }
        
        .file-name a:hover {
            color: var(--accent);
        }
        
        .file-name .dir-link {
            color: #fbbf24;
        }
        
        .file-perms {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-light);
            background: rgba(255,255,255,0.1);
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .file-size {
            font-size: 0.8rem;
            color: var(--text-light);
            text-align: right;
            min-width: 80px;
        }
        
        .file-date {
            font-size: 0.8rem;
            color: var(--text-light);
            min-width: 140px;
        }
        
        .file-actions {
            display: flex;
            gap: 4px;
        }
        
        .file-actions .btn {
            padding: 4px 8px;
            font-size: 0.75rem;
        }
        
        /* Permissions badges */
        .perm-badge {
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 4px;
            margin-left: 8px;
        }
        
        .perm-r { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        .perm-w { background: rgba(251, 191, 36, 0.2); color: #fbbf24; }
        .perm-no { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        
        /* Server info */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
        }
        
        .info-item {
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
            padding: 12px 16px;
        }
        
        .info-label {
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-light);
            margin-bottom: 4px;
        }
        
        .info-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-primary);
            word-break: break-all;
        }
        
        /* Quick paths */
        .quick-path {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            margin: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--text-primary);
            text-decoration: none;
            transition: all 0.2s;
        }
        
        .quick-path:hover {
            background: rgba(59, 130, 246, 0.1);
            border-color: var(--accent);
            color: var(--accent);
        }
        
        /* Warning banner */
        .warning-banner {
            background: linear-gradient(135deg, rgba(251, 191, 36, 0.2) 0%, rgba(239, 68, 68, 0.2) 100%);
            border: 1px solid rgba(251, 191, 36, 0.4);
            border-radius: 8px;
            padding: 12px 20px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            color: #fef3c7;
        }
        
        .warning-banner i {
            font-size: 1.5rem;
            color: #fbbf24;
        }
        
        .warning-banner .text-muted {
            color: #fcd34d !important;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .file-item {
                grid-template-columns: auto 1fr auto;
            }
            
            .file-perms, .file-date {
                display: none;
            }
        }
        
        /* Text colors */
        .text-purple { color: #a855f7; }
        .text-orange { color: #f97316; }
        .text-teal { color: #14b8a6; }
        .text-pink { color: #ec4899; }
        
        /* Tabs */
        .nav-tabs {
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }
        
        .nav-tabs .nav-link {
            color: var(--text-muted);
            border: none;
            border-bottom: 2px solid transparent;
            padding: 12px 20px;
            font-weight: 500;
        }
        
        .nav-tabs .nav-link:hover {
            color: var(--text-light);
            border-color: rgba(255,255,255,0.1);
        }
        
        .nav-tabs .nav-link.active {
            color: var(--accent);
            background: transparent;
            border-bottom-color: var(--accent);
        }
        
        /* Stats Cards */
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            height: 100%;
        }
        
        .stat-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin-bottom: 16px;
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
        }
        
        .stat-label {
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        .progress {
            background-color: rgba(255,255,255,0.1);
            height: 8px;
        }
        
        .ext-badge {
            background: rgba(255,255,255,0.05);
            color: var(--text-light);
            font-size: 0.8rem;
            padding: 6px 10px;
            border-radius: 6px;
            display: inline-block;
            margin: 2px;
            border: 1px solid transparent;
        }
        
        .ext-badge:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        
        /* Override Bootstrap's text-muted for better contrast on dark bg */
        .text-muted {
            color: #cbd5e1 !important;
        }
        
        /* Small text should still be readable */
        .small, small {
            color: #cbd5e1;
        }
        
        /* Form labels */
        label.small {
            color: #e2e8f0 !important;
        }
        
        /* Alert text */
        .alert {
            color: #1e293b;
        }
        
        .alert-warning {
            background: #fef3c7;
            border-color: #fcd34d;
            color: #92400e;
        }
        
        .alert-success {
            background: #d1fae5;
            border-color: #6ee7b7;
            color: #065f46;
        }
        
        .alert-info {
            background: #dbeafe;
            border-color: #93c5fd;
            color: #1e40af;
        }
        
        /* Form controls in dark theme */
        .form-control.bg-dark {
            background: #1e293b !important;
            color: #f1f5f9 !important;
            border-color: #475569 !important;
        }
        
        .input-group-sm .form-control {
            background: #1e293b;
            color: #f1f5f9;
            border-color: #475569;
        }
        
        .card-body p.small {
            color: #cbd5e1;
        }
        
        .card-body label.small {
            color: #e2e8f0;
        }
    </style>
</head>
<body>

<nav class="navbar">
    <span class="navbar-brand">
        <i class="fas fa-folder-tree me-2"></i> Directory Explorer
    </span>
    <div class="d-flex align-items-center gap-3">
        <span class="small" style="color: #cbd5e1;">
            <i class="fas fa-clock me-1"></i>
            <?php echo date('Y-m-d H:i:s'); ?>
        </span>
        <a href="?logout=1" class="btn btn-outline-danger btn-sm">
            <i class="fas fa-sign-out-alt me-1"></i> Logout
        </a>
    </div>
</nav>

<div class="container-fluid">
    
    <div class="warning-banner">
        <i class="fas fa-exclamation-triangle"></i>
        <div>
            <strong>⚠️ Temporary File - Delete After Use!</strong>
            <div class="small text-muted">
                This utility is for finding paths only. Leaving it on your server is a security risk.
            </div>
        </div>
    </div>
    
    <!-- Navigation Tabs -->
    <ul class="nav nav-tabs" id="mainTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="explorer-tab" data-bs-toggle="tab" data-bs-target="#explorer-pane" type="button" role="tab" aria-selected="true">
                <i class="fas fa-folder-open me-2"></i> File Explorer
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="health-tab" data-bs-toggle="tab" data-bs-target="#health-pane" type="button" role="tab" aria-selected="false">
                <i class="fas fa-heartbeat text-danger me-2"></i> Server Health
            </button>
        </li>
    </ul>
    
    <div class="tab-content">
        
        <!-- EXPLORER TAB -->
        <div class="tab-pane fade show active" id="explorer-pane" role="tabpanel">
            <div class="row g-4">
        <!-- Main file browser -->
        <div class="col-lg-8">
            
            <!-- Current path with copy button -->
            <div class="path-breadcrumb">
                <i class="fas fa-folder-open text-warning me-2"></i>
                
                <?php
                $buildPath = '';
                $isWindows = DIRECTORY_SEPARATOR === '\\';
                
                if ($isWindows) {
                    // Windows path handling
                    $segments = explode('\\', $currentPath);
                    foreach ($segments as $i => $segment) {
                        if (empty($segment)) continue;
                        $buildPath .= $segment . '\\';
                        $isLast = ($i === count($segments) - 1);
                        
                        if ($isLast) {
                            echo '<span class="current">' . htmlspecialchars($segment) . '</span>';
                        } else {
                            echo '<a href="?path=' . urlencode(rtrim($buildPath, '\\')) . '">' . htmlspecialchars($segment) . '</a>';
                            echo '<span class="separator">/</span>';
                        }
                    }
                } else {
                    // Unix path handling
                    echo '<a href="?path=/">/</a>';
                    $segments = array_filter(explode('/', $currentPath));
                    $totalSegments = count($segments);
                    $currentIndex = 0;
                    
                    foreach ($segments as $segment) {
                        $currentIndex++;
                        $buildPath .= '/' . $segment;
                        $isLast = ($currentIndex === $totalSegments);
                        
                        echo '<span class="separator">/</span>';
                        if ($isLast) {
                            echo '<span class="current">' . htmlspecialchars($segment) . '</span>';
                        } else {
                            echo '<a href="?path=' . urlencode($buildPath) . '">' . htmlspecialchars($segment) . '</a>';
                        }
                    }
                }
                ?>
                
                <button class="copy-path-btn" onclick="copyPath('<?php echo htmlspecialchars(addslashes($currentPath)); ?>')">
                    <i class="fas fa-copy"></i>
                    <span>Copy Path</span>
                </button>
            </div>
            
            <!-- File listing -->
            <div class="card file-list">
                <?php if ($error_msg): ?>
                    <div class="p-4 text-center text-danger">
                        <i class="fas fa-exclamation-circle fa-2x mb-2"></i>
                        <div><?php echo htmlspecialchars($error_msg); ?></div>
                    </div>
                <?php else: ?>
                    <?php foreach ($items as $item): ?>
                        <div class="file-item <?php echo $item['is_dir'] ? 'is-dir' : ''; ?>"
                             <?php if ($item['is_dir'] && $item['is_readable']): ?>
                             onclick="window.location='?path=<?php echo urlencode($item['path']); ?>'"
                             <?php endif; ?>>
                            
                            <!-- Icon -->
                            <div class="file-icon <?php echo $item['is_dir'] ? 'folder' : ''; ?>">
                                <i class="fas <?php echo getFileIcon($item); ?>"></i>
                            </div>
                            
                            <!-- Name -->
                            <div class="file-name">
                                <?php if ($item['is_dir'] && $item['is_readable']): ?>
                                    <a href="?path=<?php echo urlencode($item['path']); ?>" 
                                       class="dir-link"
                                       onclick="event.stopPropagation();">
                                        <?php echo htmlspecialchars($item['name']); ?>
                                    </a>
                                <?php else: ?>
                                    <?php echo htmlspecialchars($item['name']); ?>
                                <?php endif; ?>
                                
                                <?php if (!$item['is_readable']): ?>
                                    <span class="perm-badge perm-no">No Read</span>
                                <?php endif; ?>
                                
                                <?php if ($item['is_writable'] && $item['name'] !== '..'): ?>
                                    <span class="perm-badge perm-w">Writable</span>
                                <?php endif; ?>
                            </div>
                            
                            <!-- Permissions -->
                            <div class="file-perms">
                                <?php echo $item['perms']; ?>
                            </div>
                            
                            <!-- Size -->
                            <div class="file-size">
                                <?php echo $item['is_dir'] ? '<span style="color: #94a3b8;">DIR</span>' : formatBytes($item['size']); ?>
                            </div>
                            
                            <!-- Modified -->
                            <div class="file-date">
                                <?php echo $item['modified'] ? date('Y-m-d H:i', $item['modified']) : '-'; ?>
                            </div>
                            
                            <!-- Actions -->
                            <div class="file-actions">
                                <?php if (!$item['is_dir'] && $item['is_readable']): ?>
                                <button class="btn btn-outline-info btn-sm" 
                                        onclick="event.stopPropagation(); viewFile('<?php echo htmlspecialchars(addslashes($item['path'])); ?>');"
                                        title="View File">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <?php endif; ?>
                                <button class="btn btn-outline-primary btn-sm" 
                                        onclick="event.stopPropagation(); copyPath('<?php echo htmlspecialchars(addslashes($item['path'])); ?>');"
                                        title="Copy full path">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            
        </div>
        
        <!-- Sidebar -->
        <div class="col-lg-4">
            
            <!-- Quick Navigation -->
            <div class="card mb-4">
                <div class="card-header">
                    <i class="fas fa-bolt text-warning me-2"></i>
                    Quick Navigation
                </div>
                <div class="card-body">
                    <a href="?path=<?php echo urlencode($_SERVER['DOCUMENT_ROOT'] ?? '/var/www/html'); ?>" class="quick-path">
                        <i class="fas fa-globe"></i>
                        Document Root
                    </a>
                    <a href="?path=<?php echo urlencode(__DIR__); ?>" class="quick-path">
                        <i class="fas fa-file-code"></i>
                        Script Location
                    </a>
                    <a href="?path=<?php echo urlencode(dirname(__DIR__)); ?>" class="quick-path">
                        <i class="fas fa-level-up-alt"></i>
                        Parent Directory
                    </a>
                    <?php if (!$isWindows): ?>
                    <a href="?path=/var/www" class="quick-path">
                        <i class="fas fa-server"></i>
                        /var/www
                    </a>
                    <a href="?path=/home" class="quick-path">
                        <i class="fas fa-home"></i>
                        /home
                    </a>
                    <a href="?path=/tmp" class="quick-path">
                        <i class="fas fa-folder"></i>
                        /tmp
                    </a>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Server Info -->
            <div class="card mb-4">
                <div class="card-header">
                    <i class="fas fa-server text-info me-2"></i>
                    Server Information
                </div>
                <div class="card-body">
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">Document Root</div>
                            <div class="info-value"><?php echo htmlspecialchars($serverInfo['document_root']); ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">This Script</div>
                            <div class="info-value"><?php echo htmlspecialchars($serverInfo['script_file']); ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">PHP Version</div>
                            <div class="info-value"><?php echo htmlspecialchars($serverInfo['php_version']); ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Server OS</div>
                            <div class="info-value"><?php echo htmlspecialchars($serverInfo['os']); ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Running As</div>
                            <div class="info-value"><?php echo htmlspecialchars($serverInfo['user']); ?></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Server Software</div>
                            <div class="info-value"><?php echo htmlspecialchars($serverInfo['server_software']); ?></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Sentinel Config Helper -->
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-shield-halved text-success me-2"></i>
                    Sentinel Config Paths
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-3">
                        Copy these paths for your Security Sentinel configuration:
                    </p>
                    
                    <div class="mb-3">
                        <label class="small text-muted">Monitor Directory (usually document root):</label>
                        <div class="input-group input-group-sm">
                            <input type="text" class="form-control bg-dark text-light border-secondary" 
                                   value="<?php echo htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? $currentPath); ?>" 
                                   id="sentinel-monitor" readonly>
                            <button class="btn btn-outline-primary" onclick="copyFromInput('sentinel-monitor')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="small text-muted">Current Directory:</label>
                        <div class="input-group input-group-sm">
                            <input type="text" class="form-control bg-dark text-light border-secondary" 
                                   value="<?php echo htmlspecialchars($currentPath); ?>" 
                                   id="sentinel-current" readonly>
                            <button class="btn btn-outline-primary" onclick="copyFromInput('sentinel-current')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="alert alert-success small mb-0">
                        <i class="fas fa-lightbulb me-1"></i>
                        <strong>Tip:</strong> Place Security Sentinel in your document root for best results.
                    </div>
                </div>
            </div>
            
        </div>
    </div>
        </div> 
        <!-- END EXPLORER TAB -->
        
        <!-- HEALTH TAB -->
        <div class="tab-pane fade" id="health-pane" role="tabpanel">
            <div class="row g-4">
                
                <!-- Quick Stats -->
                <div class="col-md-6 col-lg-3">
                    <div class="stat-card">
                        <div class="stat-icon bg-primary bg-opacity-10 text-primary">
                            <i class="fas fa-memory"></i>
                        </div>
                        <div class="stat-value"><?php echo $serverStats['php_limits']['memory_limit']; ?></div>
                        <div class="stat-label">Memory Limit</div>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="stat-card">
                        <div class="stat-icon bg-success bg-opacity-10 text-success">
                            <i class="fas fa-upload"></i>
                        </div>
                        <div class="stat-value"><?php echo $serverStats['php_limits']['upload_max_filesize']; ?></div>
                        <div class="stat-label">Max Upload</div>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="stat-card">
                        <div class="stat-icon bg-warning bg-opacity-10 text-warning">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="stat-value"><?php echo $serverStats['php_limits']['max_execution_time']; ?></div>
                        <div class="stat-label">Max Execution Time</div>
                    </div>
                </div>
                
                <div class="col-md-6 col-lg-3">
                    <div class="stat-card">
                        <div class="stat-icon bg-info bg-opacity-10 text-info">
                            <i class="fas fa-hdd"></i>
                        </div>
                        <div class="stat-value"><?php echo $diskPercent; ?>%</div>
                        <div class="stat-label">Disk Usage</div>
                    </div>
                </div>
                
                <!-- Disk Usage Detail -->
                <div class="col-lg-6">
                    <div class="card h-100">
                        <div class="card-header">
                            <i class="fas fa-hdd text-info me-2"></i> Disk Storage
                        </div>
                        <div class="card-body">
                            <div class="mb-4">
                                <div class="d-flex justify-content-between mb-2 small">
                                    <span>Used: <?php echo formatBytes($serverStats['disk']['total'] - $serverStats['disk']['free']); ?></span>
                                    <span>Total: <?php echo formatBytes($serverStats['disk']['total']); ?></span>
                                </div>
                                <div class="progress mb-2" style="height: 20px;">
                                    <div class="progress-bar bg-info" role="progressbar" style="width: <?php echo $diskPercent; ?>%"></div>
                                </div>
                                <div class="text-end small text-muted"><?php echo formatBytes($serverStats['disk']['free']); ?> Free</div>
                            </div>
                            
                            <hr class="border-secondary">
                            
                            <div class="row g-3">
                                <div class="col-6">
                                    <div class="info-label">POST Max Size</div>
                                    <div class="info-value"><?php echo $serverStats['php_limits']['post_max_size']; ?></div>
                                </div>
                                <div class="col-6">
                                    <div class="info-label">Max Input Vars</div>
                                    <div class="info-value"><?php echo $serverStats['php_limits']['max_input_vars']; ?></div>
                                </div>
                                <div class="col-6">
                                    <div class="info-label">Opcache Enabled</div>
                                    <div class="info-value">
                                        <?php if ($serverStats['opcache'] && $serverStats['opcache']['opcache_enabled']): ?>
                                            <span class="text-success"><i class="fas fa-check-circle"></i> Yes</span>
                                        <?php else: ?>
                                            <span class="text-muted"><i class="fas fa-times-circle"></i> No</span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div class="col-6">
                                    <div class="info-label">PHP API</div>
                                    <div class="info-value"><?php echo php_sapi_name(); ?></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Extensions -->
                <div class="col-lg-6">
                    <div class="card h-100">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span>
                                <i class="fas fa-puzzle-piece text-purple me-2"></i> 
                                Loaded Extensions
                                <span class="badge bg-secondary ms-2"><?php echo count($serverStats['extensions']); ?></span>
                            </span>
                            <input type="text" id="extSearch" class="form-control form-control-sm bg-dark text-light border-secondary" 
                                   style="width: 150px;" placeholder="Search..." onkeyup="filterExtensions()">
                        </div>
                        <div class="card-body">
                            <div id="extensionList" style="max-height: 250px; overflow-y: auto;">
                                <?php foreach ($serverStats['extensions'] as $ext): ?>
                                    <span class="ext-badge"><?php echo htmlspecialchars($ext); ?></span>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
            </div>
        </div>
        <!-- END HEALTH TAB -->
        
    </div>
    
</div>


<!-- Toast notification -->
<div class="position-fixed bottom-0 end-0 p-3" style="z-index: 9999;">
    <div id="copyToast" class="toast align-items-center text-bg-success border-0" role="alert">
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas fa-check-circle me-2"></i>
                <span id="toastMessage">Path copied to clipboard!</span>
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

<!-- File Viewer Modal -->
<div class="modal fade" id="fileViewerModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content" style="background: #1e293b; color: #f8fafc; border: 1px solid #475569;">
            <div class="modal-header" style="border-bottom: 1px solid #475569;">
                <h5 class="modal-title" id="fileViewerTitle" style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;"></h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body p-0">
                <pre id="fileViewerContent" style="margin: 0; padding: 20px; color: #e2e8f0; font-family: 'JetBrains Mono', monospace; white-space: pre-wrap; font-size: 0.85rem;"></pre>
            </div>
            <div class="modal-footer" style="border-top: 1px solid #475569;">
                <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<script>
// Tab Persistence
document.addEventListener('DOMContentLoaded', function() {
    // Restore tab from URL hash
    let hash = window.location.hash;
    if (hash) {
        let triggerEl = document.querySelector(`.nav-link[data-bs-target="${hash}"]`);
        if (triggerEl) {
            new bootstrap.Tab(triggerEl).show();
        }
    }
    
    // Update URL hash on tab change
    let tabEls = document.querySelectorAll('button[data-bs-toggle="tab"]');
    tabEls.forEach(function(tabEl) {
        tabEl.addEventListener('shown.bs.tab', function (event) {
            let target = event.target.getAttribute('data-bs-target');
            history.replaceState(null, null, target);
        });
    });
});

function filterExtensions() {
    let input = document.getElementById('extSearch');
    let filter = input.value.toLowerCase();
    let container = document.getElementById('extensionList');
    let badges = container.getElementsByClassName('ext-badge');
    
    for (let i = 0; i < badges.length; i++) {
        let txtValue = badges[i].textContent || badges[i].innerText;
        if (txtValue.toLowerCase().indexOf(filter) > -1) {
            badges[i].style.display = "";
        } else {
            badges[i].style.display = "none";
        }
    }
}

function viewFile(path) {
    const modal = new bootstrap.Modal(document.getElementById('fileViewerModal'));
    const titleEl = document.getElementById('fileViewerTitle');
    const contentEl = document.getElementById('fileViewerContent');
    
    titleEl.textContent = 'Loading...';
    contentEl.textContent = 'Fetching file content...';
    modal.show();
    
    fetch('?action=view_file&file=' + encodeURIComponent(path))
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                titleEl.textContent = data.path;
                contentEl.textContent = data.content;
            } else {
                titleEl.textContent = 'Error';
                contentEl.textContent = data.error; // Use textContent for safety
                contentEl.classList.add('text-danger');
            }
        })
        .catch(err => {
            titleEl.textContent = 'Error';
            contentEl.textContent = 'Failed to load file. ' + err;
        });
}

function copyPath(path) {
    navigator.clipboard.writeText(path).then(() => {
        showToast('Path copied: ' + path.substring(0, 50) + (path.length > 50 ? '...' : ''));
        
        // Visual feedback on button
        event.target.closest('button').classList.add('copied');
        setTimeout(() => {
            event.target.closest('button').classList.remove('copied');
        }, 1500);
    }).catch(err => {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = path;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Path copied!');
    });
}

function copyFromInput(inputId) {
    const input = document.getElementById(inputId);
    input.select();
    navigator.clipboard.writeText(input.value).then(() => {
        showToast('Copied!');
    });
}

function showToast(message) {
    document.getElementById('toastMessage').textContent = message;
    const toast = new bootstrap.Toast(document.getElementById('copyToast'));
    toast.show();
}
</script>

</body>
</html>
<?php