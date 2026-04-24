package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/mrthoabby/serverpilot/internal/auth"
	"github.com/spf13/cobra"
)

var resetPassword bool

var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Show or reset the admin credentials",
	Long: `Displays the configured admin username and config file location.
The password is stored as a bcrypt hash and cannot be shown in plain text.

Use --reset to change the password for the current admin user.

Examples:
  sp credentials           # show current admin info
  sp credentials --reset   # reset the admin password`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := auth.LoadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "No credentials configured.")
			fmt.Fprintln(os.Stderr, "Run 'sp setup' to create admin credentials.")
			return err
		}

		fmt.Println("=== ServerPilot Credentials ===")
		fmt.Println()
		fmt.Printf("  Username:    %s\n", config.Username)
		fmt.Printf("  Password:    ******** (bcrypt hash — cannot be shown)\n")
		fmt.Printf("  Config file: /etc/serverpilot/config.json\n")
		fmt.Println()

		if !resetPassword {
			fmt.Println("To reset the password, run: sp credentials --reset")
			return nil
		}

		// Reset password flow.
		fmt.Println("--- Reset Password ---")
		fmt.Println()

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter new password (min 8 characters): ")
		newPassword, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		newPassword = strings.TrimSpace(newPassword)
		if len(newPassword) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}

		fmt.Print("Confirm new password: ")
		confirmPassword, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		confirmPassword = strings.TrimSpace(confirmPassword)

		if newPassword != confirmPassword {
			return fmt.Errorf("passwords do not match")
		}

		if err := auth.ResetPassword(config, newPassword); err != nil {
			return fmt.Errorf("failed to reset password: %w", err)
		}

		fmt.Println()
		fmt.Printf("  ✓ Password updated for user '%s'.\n", config.Username)

		// Restart daemon if running so it picks up the new config.
		if IsRunningAsDaemon() {
			fmt.Println()
			if err := RestartDaemon(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: password updated but daemon restart failed: %v\n", err)
			}
		}

		return nil
	},
}

func init() {
	credentialsCmd.Flags().BoolVar(&resetPassword, "reset", false, "Reset the admin password")
	rootCmd.AddCommand(credentialsCmd)
}
