import Users from "../models/userModel.js";
import { compareString, createJWT, hashString } from "../utils/index.js";
import { sendVerificationEmail } from "../utils/sendVerificationEmail.js";

export const register = async (req, res, next)=>{

    const {firstName, lastName, email, password } = req.body;

    if(!(firstName || lastName || email || password)){
        next("Provide required Field")
        return;
    }

    try{
        const userExist = await Users.findOne({email})

        if(userExist){

            next("This email already exists ");
            return
        }

        const hashedPassword = await hashString(password);

        const user = await Users.create({
            firstName,
            lastName,
            email,
            password: hashedPassword,
        });

        //Verification email send

        sendVerificationEmail(user,res);


    }
    catch(error){
        console.log(error)

        res.status(404).json({message : error.message})

    }

}


export const login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: "failed",
        message: "Please Provide User Credentials",
      });
    }

    // Find user by email
    const user = await Users.findOne({ email }).select("+password").populate({
      path: "friends",
      select: "firstName lastName location profileUrl -password",
    });

    if (!user) {
      return res.status(400).json({
        success: "failed",
        message: "Invalid email or password",
      });
    }

    if (!user?.verified) {
      return res.status(400).json({
        success: "failed",
        message: "User email is not verified. Check your email account and verify your email",
      });
    }

    // Compare password
    const isMatch = await compareString(password, user?.password);

    if (!isMatch) {
      return res.status(400).json({
        success: "failed",
        message: "Invalid email or password",
      });
    }

    user.password = undefined;

    const token = createJWT(user?._id);

    return res.status(200).json({
      success: true,
      message: "Login successfully",
      user,
      token,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: "failed",
      message: error.message || "Something went wrong",
    });
  }
};
