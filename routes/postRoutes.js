import express from "express"
import userAuth from "../middleware/authMiddleware.js"
import { commentPost, createPost, deletePost, getComments, getPosts, getSinglePost, getUserPost, likePost, likePostComment, replyPostComment } from "../controllers/postController.js";

const router = express.Router();

// create post
router.post("/create-post",userAuth,createPost)

// get posts
router.post("/", userAuth, getPosts);
router.post("/:id", userAuth, getSinglePost);

router.post("/get-user-post/:id", userAuth, getUserPost);

// get comments
router.get("/comments/:postId", getComments);

//like and comment on posts
router.post("/like/:id", userAuth, likePost);
router.post("/like-comment/:id/:rid?", userAuth, likePostComment);
router.post("/comment/:id", userAuth, commentPost);
router.post("/reply-comment/:id", userAuth, replyPostComment);

//delete post
router.delete("/:id", userAuth, deletePost);


export default router;