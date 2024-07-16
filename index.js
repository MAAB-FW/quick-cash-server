const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 5000;
const bcrypt = require("bcrypt");

const app = express();

// middleware
app.use(express.json());
app.use(cookieParser());
//Must remove "/" from your production URL
app.use(
    cors({
        origin: ["http://localhost:5173"],
        credentials: true,
    }),
);

const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
}

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        // Send a ping to confirm a successful connection
        const db = client.db("QuickCashDB");
        const usersCollection = db.collection("users");

        app.post("/jwt", (req, res) => {
            const user = req.body
            const token = jwt.sign(user, process.env.TOKEN_SECRET, { expiresIn: "365d" })
            res.cookie("token", token, cookieOptions).send({ success: true })
        })

        app.get("/users", async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        app.post("/login/:email", async (req, res) => {
            const email = req.params.email;
            const pin = req.body.pin;
            const user = await usersCollection.findOne({ email });
            const pinMatching = bcrypt.compareSync(pin, user.hashPin);
            if (!pinMatching || !user) {
                return res.send({ message: "Invalid credentials!", status: 403 });
            }
            res.send(user);
        });

        app.post("/createUser", async (req, res) => {
            const user = req.body;
            const hashPin = bcrypt.hashSync(user.pin, 10);
            const isExist = await usersCollection.findOne({ email: user.email });
            if (isExist) {
                return res.send({ message: "user already exist!", status: isExist.status });
            }
            const doc = {
                ...user,
                hashPin,
            };
            const result = await usersCollection.insertOne(doc);
            res.send(result);
        });

        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get("/", (req, res) => {
    res.send("QuickCash is running...");
});

app.listen(port, () => {
    console.log("QuickCash server running on", port);
});
