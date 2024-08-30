export default () => ({
    database: {
        connectionString: process.env.DATABASE_URL,
    },
    jwt: {
        secret: process.env.JWT_SECRET,
    },
    rt: {
        secret: process.env.RT_SECRET,
    }
});