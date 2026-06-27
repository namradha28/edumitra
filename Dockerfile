# Step 1: Use an official Node.js runtime as a parent image
FROM node:18

# Step 2: Set the working directory inside the cloud container
WORKDIR /usr/src/app

# Step 3: Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Step 4: Copy the rest of your app's source code
COPY . .

# Step 5: Expose the port and start your server
EXPOSE 8080
CMD [ "node", "server.js" ]