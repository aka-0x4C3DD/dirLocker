package gui

import (
	"fmt"
	"runtime"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"dirLocker/pkg/logging"
)

// NotificationType represents the type of notification
type NotificationType int

const (
	NotificationInfo NotificationType = iota
	NotificationSuccess
	NotificationWarning
	NotificationError
)

// Notification represents a system notification
type Notification struct {
	Type    NotificationType
	Title   string
	Message string
}

// NotificationManager handles system notifications
type NotificationManager struct {
	logger *logging.Logger
	app    fyne.App
}

// NewNotificationManager creates a new notification manager
func NewNotificationManager(app fyne.App, logger *logging.Logger) *NotificationManager {
	return &NotificationManager{
		logger: logger,
		app:    app,
	}
}

// SendNotification sends a system notification
func (nm *NotificationManager) SendNotification(notification *Notification) {
	nm.logger.Info("Sending notification", "type", notification.Type, "title", notification.Title)

	// Try to send native OS notification first
	if nm.sendNativeNotification(notification) {
		return
	}

	// Fallback to in-app notification
	nm.sendInAppNotification(notification)
}

// sendNativeNotification attempts to send a native OS notification
func (nm *NotificationManager) sendNativeNotification(notification *Notification) bool {
	switch runtime.GOOS {
	case "windows":
		return nm.sendWindowsNotification(notification)
	case "darwin":
		return nm.sendMacOSNotification(notification)
	case "linux":
		return nm.sendLinuxNotification(notification)
	default:
		nm.logger.Warn("Native notifications not supported on this platform", "os", runtime.GOOS)
		return false
	}
}

// sendWindowsNotification sends a Windows Toast notification
func (nm *NotificationManager) sendWindowsNotification(notification *Notification) bool {
	// TODO: Implement Windows Toast notifications
	// For now, use Fyne's built-in notification system
	nm.logger.Debug("Windows native notifications not yet implemented")
	return false
}

// sendMacOSNotification sends a macOS Notification Center notification
func (nm *NotificationManager) sendMacOSNotification(notification *Notification) bool {
	// TODO: Implement macOS Notification Center notifications
	// For now, use Fyne's built-in notification system
	nm.logger.Debug("macOS native notifications not yet implemented")
	return false
}

// sendLinuxNotification sends a Linux libnotify notification
func (nm *NotificationManager) sendLinuxNotification(notification *Notification) bool {
	// TODO: Implement Linux libnotify notifications
	// For now, use Fyne's built-in notification system
	nm.logger.Debug("Linux native notifications not yet implemented")
	return false
}

// sendInAppNotification sends an in-app notification using Fyne
func (nm *NotificationManager) sendInAppNotification(notification *Notification) {
	// Use Fyne's notification system as fallback
	nm.app.SendNotification(&fyne.Notification{
		Title:   notification.Title,
		Content: notification.Message,
	})
}

// Convenience methods for different notification types

// SendInfo sends an info notification
func (nm *NotificationManager) SendInfo(title, message string) {
	nm.SendNotification(&Notification{
		Type:    NotificationInfo,
		Title:   title,
		Message: message,
	})
}

// SendSuccess sends a success notification
func (nm *NotificationManager) SendSuccess(title, message string) {
	nm.SendNotification(&Notification{
		Type:    NotificationSuccess,
		Title:   title,
		Message: message,
	})
}

// SendWarning sends a warning notification
func (nm *NotificationManager) SendWarning(title, message string) {
	nm.SendNotification(&Notification{
		Type:    NotificationWarning,
		Title:   title,
		Message: message,
	})
}

// SendError sends an error notification
func (nm *NotificationManager) SendError(title, message string) {
	nm.SendNotification(&Notification{
		Type:    NotificationError,
		Title:   title,
		Message: message,
	})
}

// Progress notification for long-running operations
type ProgressNotification struct {
	Title     string
	Message   string
	Progress  float64 // 0.0 to 1.0
	IsVisible bool
	widget    *widget.ProgressBar
	container *fyne.Container
}

// NewProgressNotification creates a new progress notification
func NewProgressNotification(title, message string) *ProgressNotification {
	progress := widget.NewProgressBar()
	progress.SetValue(0.0)

	label := widget.NewLabel(message)
	titleLabel := widget.NewRichTextFromMarkdown(fmt.Sprintf("**%s**", title))

	cardContent := container.NewVBox(
		titleLabel,
		label,
		progress,
	)

	_ = widget.NewCard(title, "", cardContent) // Create card but don't store it for now

	return &ProgressNotification{
		Title:     title,
		Message:   message,
		Progress:  0.0,
		IsVisible: false,
		widget:    progress,
		container: cardContent,
	}
}

// UpdateProgress updates the progress value
func (pn *ProgressNotification) UpdateProgress(progress float64, message string) {
	pn.Progress = progress
	pn.Message = message
	pn.widget.SetValue(progress)
}

// Show shows the progress notification
func (pn *ProgressNotification) Show() {
	pn.IsVisible = true
	// TODO: Add to main window overlay or status area
}

// Hide hides the progress notification
func (pn *ProgressNotification) Hide() {
	pn.IsVisible = false
	// TODO: Remove from main window overlay or status area
}
