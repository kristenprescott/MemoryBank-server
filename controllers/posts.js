import express from "express";
import mongoose from "mongoose";
import PostMessage from "../models/postMessage.js";

// GET all posts
export const getPosts = async (req, res) => {
  try {
    const postMessages = await PostMessage.find();
    res.status(200).json(postMessages);
    // 200: OK
  } catch (error) {
    res.status(404).json({ message: error.message });
    // 404: Not Found
  }
};

// CREATE new post
export const createPost = async (req, res) => {
  const post = req.body;
  const newPost = new PostMessage(post);
  try {
    await newPost.save();
    res.status(201).json(newPost);
    // 201: Created
  } catch (error) {
    res.status(409).json({ message: error.message });
    // 409: Conflict
  }
};

// UPDATE a post
export const updatePost = async (req, res) => {
  const { id: _id } = req.params;
  const post = req.body;

  if (!mongoose.Types.ObjectId.isValid(_id)) {
    return res.status(404).send("Invalid post id.");
  }

  const updatedPost = await PostMessage.findByIdAndUpdate(
    _id,
    { ...post, _id },
    {
      new: true,
    }
  );

  res.json(updatedPost);
};

// DELETE a post
export const deletePost = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(404).send("Invalid post id.");
  }

  await PostMessage.findByIdAndRemove(id);

  res.json({ message: "Post deleted." });
};

// LIKE a post
export const likePost = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(404).send("Invalid post id.");
  }

  const post = await PostMessage.findById(id);
  const updatedPost = await PostMessage.findByIdAndUpdate(
    id,
    { likeCount: post.likeCount + 1 },
    { new: true }
  );

  res.json(updatedPost);
};
