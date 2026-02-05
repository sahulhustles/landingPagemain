// Authentication Service using Supabase Auth
class AuthService {
    constructor() {
        this.supabase = null;
        this.currentUser = null;
        // Only allow this admin email to access the panel
        this.ADMIN_EMAIL = 'b.sahulhameed1@gmail.com';
    }

    initializeClient(supabaseUrl, supabaseAnonKey) {
        if (typeof supabase !== 'undefined') {
            this.supabase = supabase.createClient(supabaseUrl, supabaseAnonKey);
            this.setupAuthListener();
        }
    }

    // Set up auth state listener
    setupAuthListener() {
        if (!this.supabase) return;

        this.supabase.auth.onAuthStateChange(async (event, session) => {
            console.log('Auth state changed:', event);
            this.currentUser = session?.user || null;
            
            // If user is logged in but not the admin, sign them out
            if (this.currentUser && this.currentUser.email !== this.ADMIN_EMAIL) {
                console.log('Non-admin user detected, signing out...');
                await this.signOut();
                window.location.href = 'admin-login.html?error=unauthorized';
                return;
            }
            
            // Dispatch custom event for other parts of the app
            window.dispatchEvent(new CustomEvent('authStateChanged', {
                detail: { event, session, user: this.currentUser }
            }));
        });
    }

    // Check if current user is admin
    async isAdmin() {
        if (!this.currentUser) return false;
        return this.currentUser.email === this.ADMIN_EMAIL;
    }

    // Sign in with email and password
    async signIn(email, password) {
        try {
            if (!this.supabase) {
                throw new Error('Supabase not initialized');
            }
            
            // Only allow admin email to sign in
            if (email !== this.ADMIN_EMAIL) {
                throw new Error('Access denied. Admin access only.');
            }

            const { data, error } = await this.supabase.auth.signInWithPassword({
                email,
                password,
            });

            if (error) throw error;
            
            // Verify the signed in user is the admin
            if (data.user.email !== this.ADMIN_EMAIL) {
                await this.signOut();
                throw new Error('Access denied. Admin access only.');
            }

            return { success: true, data };
        } catch (error) {
            console.error('Sign in error:', error);
            return { 
                success: false, 
                error: error.message || 'Failed to sign in. Please check your credentials.'
            };
        }
    }

    // Sign in
    async signIn(email, password) {
        try {
            if (!this.supabase) {
                throw new Error('Supabase not initialized');
            }

            const { data, error } = await this.supabase.auth.signInWithPassword({
                email,
                password,
            });

            if (error) throw error;

            this.currentUser = data.user;
            return { success: true, data, user: data.user };
        } catch (error) {
            console.error('Sign in error:', error);
            return { success: false, error: error.message };
        }
    }

    // Sign out
    async signOut() {
        try {
            if (!this.supabase) {
                throw new Error('Supabase not initialized');
            }

            const { error } = await this.supabase.auth.signOut();
            if (error) throw error;

            this.currentUser = null;
            return { success: true };
        } catch (error) {
            console.error('Sign out error:', error);
            return { success: false, error: error.message };
        }
    }

    // Get current session
    async getSession() {
        try {
            if (!this.supabase) {
                return { success: false, session: null };
            }

            const { data: { session }, error } = await this.supabase.auth.getSession();
            
            if (error) throw error;

            this.currentUser = session?.user || null;
            return { success: true, session, user: this.currentUser };
        } catch (error) {
            console.error('Get session error:', error);
            return { success: false, error: error.message, session: null };
        }
    }

    // Get current user
    async getCurrentUser() {
        try {
            if (!this.supabase) {
                return { success: false, user: null };
            }

            const { data: { user }, error } = await this.supabase.auth.getUser();
            
            if (error) throw error;

            this.currentUser = user;
            return { success: true, user };
        } catch (error) {
            console.error('Get user error:', error);
            return { success: false, error: error.message, user: null };
        }
    }

    // Check if user is authenticated
    async isAuthenticated() {
        const { session } = await this.getSession();
        return !!session;
    }

    // Reset password
    async resetPassword(email) {
        try {
            if (!this.supabase) {
                throw new Error('Supabase not initialized');
            }

            const { error } = await this.supabase.auth.resetPasswordForEmail(email, {
                redirectTo: `${window.location.origin}/admin-login.html`,
            });

            if (error) throw error;

            return { success: true, message: 'Password reset email sent' };
        } catch (error) {
            console.error('Reset password error:', error);
            return { success: false, error: error.message };
        }
    }

    // Update password
    async updatePassword(newPassword) {
        try {
            if (!this.supabase) {
                throw new Error('Supabase not initialized');
            }

            const { error } = await this.supabase.auth.updateUser({
                password: newPassword
            });

            if (error) throw error;

            return { success: true, message: 'Password updated successfully' };
        } catch (error) {
            console.error('Update password error:', error);
            return { success: false, error: error.message };
        }
    }
}

// Create global instance
const authService = new AuthService();

// Initialize when Supabase config is loaded
if (typeof supabaseUrl !== 'undefined' && typeof supabaseAnonKey !== 'undefined') {
    authService.initializeClient(supabaseUrl, supabaseAnonKey);
}
