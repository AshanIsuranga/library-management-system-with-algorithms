require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = 3000;

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Set up EJS as the template engine
app.set('view engine', 'ejs');

// User schema with borrowed books
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  borrowedBooks: [{
    bookId: { type: mongoose.Schema.Types.ObjectId, ref: 'Book' },
    borrowedAt: { type: Date },
    returnBy: { type: Date },
    lateFees: { type: Number, default: 0 }
  }]
});

const User = mongoose.model('User', UserSchema);

// Admin schema
const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const Admin = mongoose.model('Admin', AdminSchema);

// Book schema with availability, reservation queue, and borrow count
const BookSchema = new mongoose.Schema({
  title: { type: String, required: true, unique: true },
  author: { type: String, required: true },
  category: { type: String, required: true },
  isAvailable: { type: Boolean, default: true },
  currentBorrower: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reservationQueue: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reservedAt: { type: Date },
    position: { type: Number }
  }],
  reservationCount: { type: Number, default: 0 },
  borrowCount: { type: Number, default: 0 } // Track number of times book is borrowed
});

// Add method to get queue position
BookSchema.methods.getQueuePosition = function(userId) {
  const reservation = this.reservationQueue.find(r => r.userId.equals(userId));
  return reservation ? reservation.position : -1;
}

const Book = mongoose.model('Book', BookSchema);

// Utility functions for book management
function calculateReturnTime(borrowTime) {
  const returnTime = new Date(borrowTime);
  returnTime.setMinutes(returnTime.getMinutes() + 5);
  return returnTime;
}

function calculateLateFees(returnBy) {
  if (new Date() <= returnBy) return 0;
  const minutesLate = Math.floor((new Date() - returnBy) / (1000 * 60));
  return minutesLate; // $1 per minute late
}

// Passport configuration
passport.use('user-local', new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) return done(null, false, { message: 'Incorrect email' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false, { message: 'Incorrect password' });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Admin Local Strategy
passport.use('admin-local', new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const admin = await Admin.findOne({ email });
    if (!admin) return done(null, false, { message: 'Incorrect email' });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return done(null, false, { message: 'Incorrect password' });

    return done(null, admin);
  } catch (err) {
    return done(err);
  }
}));

// JWT Strategy
passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: '#'
}, async (jwt_payload, done) => {
  try {
    const user = await User.findById(jwt_payload.sub);
    if (user) return done(null, user);
    
    const admin = await Admin.findById(jwt_payload.sub);
    if (admin) return done(null, admin);
    
    return done(null, false);
  } catch (err) {
    return done(err, false);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    if (!user) {
      const admin = await Admin.findById(id);
      done(null, admin);
    } else {
      done(null, user);
    }
  } catch (err) {
    done(err, null);
  }
});

// Middleware configuration
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: '##',
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user instanceof Admin) {
    return next();
  }
  res.redirect('/admin/login');
}

// Home route with borrowed books
app.get('/', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('borrowedBooks.bookId');
    res.render('home', { 
      username: req.user.username,
      isAdmin: req.user instanceof Admin,
      borrowedBooks: user.borrowedBooks,
      calculateLateFees
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// User signup routes
app.get('/signup', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.send('<script>alert("User already registered!"); window.location.href="/signup";</script>');
    }
    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hash });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// User login routes
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.render('login', { error: null });
});

app.post('/login', (req, res, next) => {
  passport.authenticate('user-local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.render('login', { error: info.message || null });
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});

// Admin routes
app.get('/admin', isAdmin, (req, res) => {
  res.render('admin_dashboard', { username: req.user.username });
});

app.get('/admin/signup', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/admin');
  res.render('admin_signup');
});

app.post('/admin/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingAdmin = await Admin.findOne({ $or: [{ username }, { email }] });
    if (existingAdmin) {
      return res.send('<script>alert("Admin already registered!"); window.location.href="/admin/signup";</script>');
    }
    const hash = await bcrypt.hash(password, 10);
    const admin = new Admin({ username, email, password: hash });
    await admin.save();
    res.redirect('/admin/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/admin/login', (req, res) => {
  if (req.isAuthenticated() && req.user instanceof Admin) return res.redirect('/admin');
  res.render('admin_login', { error: null });
});

app.post('/admin/login', (req, res, next) => {
  passport.authenticate('admin-local', (err, admin, info) => {
    if (err) return next(err);
    if (!admin) return res.render('admin_login', { error: info.message || null });
    req.logIn(admin, (err) => {
      if (err) return next(err);
      return res.redirect('/admin');
    });
  })(req, res, next);
});

// Book management routes
app.get('/admin/add-book', isAdmin, (req, res) => {
  res.render('add_book');
});

app.post('/admin/add-book', isAdmin, async (req, res) => {
  const { title, author, category } = req.body;
  try {
    // Check if book with the same title already exists
    const existingBook = await Book.findOne({ title });
    if (existingBook) {
      return res.send('<script>alert("A book with this title already exists!"); window.location.href="/admin/add-book";</script>');
    }

    const book = new Book({ title, author, category });
    await book.save();
    res.redirect('/admin');
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.send('<script>alert("A book with this title already exists!"); window.location.href="/admin/add-book";</script>');
    }
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Updated book list route with search and filter functionality
// Updated book list route with improved search and filter functionality
app.get('/books', isAuthenticated, async (req, res) => {
  try {
    // Extract filter and pagination parameters
    const { category, author, title, mostBorrowed, page = 1 } = req.query;
    const limit = 10; // Number of books per page
    const skip = (page - 1) * limit;

    // Build filter object
    const filter = {};
    
    if (category) filter.category = category;
    if (author) filter.author = { $regex: author, $options: 'i' };
    if (title) filter.title = { $regex: title, $options: 'i' };

    // Prepare query
    let query = Book.find(filter);

    // Apply most borrowed filter
    if (mostBorrowed) {
      query = query.sort({ borrowCount: -1 });
    }

    // Execute query with pagination
    const totalBooks = await Book.countDocuments(filter);
    const totalPages = Math.ceil(totalBooks / limit);
    
    const books = await query
      .skip(skip)
      .limit(limit)
      .populate('currentBorrower', 'username')
      .populate('reservationQueue.userId', 'username');
    
    // Get user and other details
    const user = await User.findById(req.user._id).populate('borrowedBooks.bookId');
    
    // Get unique categories for filter dropdown
    const categories = [
      'Fantasy', 'Science Fiction', 'Romance', 'Novel', 
      'Educational', 'Historical', 'Biography', 'Other'
    ];

    // Get unique authors from the current book collection
    const authors = await Book.distinct('author');

    res.render('book_list', { 
      books,
      user,
      isAdmin: req.user instanceof Admin,
      calculateLateFees,
      moment: require('moment'),
      categories,
      authors,
      selectedCategory: category || '',
      selectedAuthor: author || '',
      searchTitle: title || '',
      mostBorrowedChecked: mostBorrowed || false,
      currentPage: parseInt(page),
      totalPages,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Book borrowing route
app.post('/books/:id/borrow', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ message: 'Book not found' });
    
    if (!book.isAvailable) {
      return res.status(400).json({ message: 'Book is not available' });
    }

    const borrowTime = new Date();
    const returnTime = calculateReturnTime(borrowTime);

    // Update book status and increment borrow count
    book.isAvailable = false;
    book.currentBorrower = req.user._id;
    book.borrowCount++; // Increment borrow count
    await book.save();

    // Update user's borrowed books
    await User.findByIdAndUpdate(req.user._id, {
      $push: {
        borrowedBooks: {
          bookId: book._id,
          borrowedAt: borrowTime,
          returnBy: returnTime
        }
      }
    });

    res.redirect('/books');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Book reservation route
// Modified reservation route to handle queue positions
app.post('/books/:id/reserve', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ message: 'Book not found' });

    // Check if user already borrowed or reserved
    const alreadyBorrowed = book.currentBorrower && book.currentBorrower.equals(req.user._id);
    const alreadyReserved = book.reservationQueue.some(
      reservation => reservation.userId.equals(req.user._id)
    );

    if (alreadyBorrowed) {
      return res.status(400).json({ message: 'You have already borrowed this book' });
    }

    if (alreadyReserved) {
      return res.status(400).json({ message: 'You have already reserved this book' });
    }

    // Add user to reservation queue with position
    const position = book.reservationQueue.length + 1;
    book.reservationQueue.push({
      userId: req.user._id,
      reservedAt: new Date(),
      position: position
    });
    book.reservationCount = position;
    await book.save();

    res.redirect('/books');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Modified return route to handle queue
app.post('/books/:id/return', isAuthenticated, async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    if (!book) return res.status(404).json({ message: 'Book not found' });

    const user = await User.findById(req.user._id);
    const borrowedBook = user.borrowedBooks.find(
      b => b.bookId.equals(book._id)
    );

    if (!borrowedBook) {
      return res.status(400).json({ message: 'You have not borrowed this book' });
    }

    // Calculate late fees
    const lateFees = calculateLateFees(borrowedBook.returnBy);
    borrowedBook.lateFees = lateFees;

    // Remove book from user's borrowed books
    await User.findByIdAndUpdate(req.user._id, {
      $pull: { borrowedBooks: { bookId: book._id } }
    });

    // Handle reservation queue
    if (book.reservationQueue.length > 0) {
      const nextReservation = book.reservationQueue.shift();
      const borrowTime = new Date();
      const returnTime = calculateReturnTime(borrowTime);

      // Update queue positions
      book.reservationQueue.forEach(reservation => {
        reservation.position--;
      });
      book.reservationCount = book.reservationQueue.length;

      // Increment borrow count
      book.borrowCount++; // Add this line to increase borrow count

      // Automatically lend to next person in queue
      book.currentBorrower = nextReservation.userId;
      book.isAvailable = false; // Ensure book is not marked as available

      await User.findByIdAndUpdate(nextReservation.userId, {
        $push: {
          borrowedBooks: {
            bookId: book._id,
            borrowedAt: borrowTime,
            returnBy: returnTime
          }
        }
      });
    } else {
      // If no reservations, make book available
      book.isAvailable = true;
      book.currentBorrower = null;
      book.reservationCount = 0;
    }
    await book.save();

    res.redirect('/books');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Logout routes
app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});

app.get('/admin/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/admin/login');
  });
});

// Protected route (for testing JWT)
app.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.render('protected');
});

// Start server

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));